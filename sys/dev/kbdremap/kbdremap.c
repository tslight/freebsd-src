/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Toby Slight
 *
 * Remaps HID usage codes for ukbd and hkbd
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ctype.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/sbuf.h>
#include <sys/sysctl.h>

#include <machine/atomic.h>
#include <machine/cpu.h>

/* avoid including complex hidbus.h macros */
typedef const uint8_t *(*hidbus_kbd_remap_fn_t)(void);
int hidbus_register_kbd_remap_hook(hidbus_kbd_remap_fn_t fn);
void hidbus_unregister_kbd_remap_hook(hidbus_kbd_remap_fn_t fn);

#define KBDREMAP_MAX_RULES 128

struct kbdremap_rule {
	uint8_t from;
	uint8_t to;
};

static struct {
	struct kbdremap_rule rules[KBDREMAP_MAX_RULES];
	int count;
	uint8_t map[256];
	volatile uintptr_t active_map_ptr;
	struct mtx mtx;
} kbdremap_state;

MTX_SYSINIT(kbdremap_mtx, &kbdremap_state.mtx, "kbdremap", MTX_DEF);

static char *
kbdremap_trim(char *s)
{
	char *e;
	while (*s && isspace((unsigned char)*s))
		s++;
	if (*s == '\0')
		return (s);
	e = s + strlen(s) - 1;
	while (e > s && isspace((unsigned char)*e))
		*e-- = '\0';
	return (s);
}

static int
kbdremap_parse_hex(const char *s, uint8_t *out)
{
	unsigned int val;
	int i;

	if (s == NULL || *s == '\0')
		return (-1);

	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
		s += 2;

	if (*s == '\0')
		return (-1);

	val = 0;
	for (i = 0; s[i] != '\0'; i++) {
		if (i >= 2)
			return (-1);
		val <<= 4;
		if (s[i] >= '0' && s[i] <= '9')
			val |= s[i] - '0';
		else if (s[i] >= 'a' && s[i] <= 'f')
			val |= s[i] - 'a' + 10;
		else if (s[i] >= 'A' && s[i] <= 'F')
			val |= s[i] - 'A' + 10;
		else
			return (-1);
	}

	if (val > 0xFF)
		return (-1);

	*out = (uint8_t)val;
	return (0);
}

static const uint8_t *
kbdremap_get_map(void)
{
	u_long v;
	v = atomic_load_acq_long(
	    (volatile u_long *)&kbdremap_state.active_map_ptr);
	if (v == 0)
		return (NULL);
	return ((const uint8_t *)(uintptr_t)v);
}

static int
sysctl_kbdremap_rules(SYSCTL_HANDLER_ARGS)
{
	char buf[1024];
	char *p, *pair, *from_str, *to_str;
	int error, i, new_count;
	struct kbdremap_rule new_rules[KBDREMAP_MAX_RULES];
	uint8_t from, to;
	uint8_t new_map[256];
	bool has_rules;
	bool seen[256] = { false };
	bool dup_warn = false;
	struct sbuf *sb;

	sb = sbuf_new_auto();
	if (sb == NULL)
		return (ENOMEM);
	mtx_lock(&kbdremap_state.mtx);
	for (i = 0; i < kbdremap_state.count; i++) {
		if (i > 0)
			sbuf_putc(sb, ',');
		sbuf_printf(sb, "0x%02x:0x%02x", kbdremap_state.rules[i].from,
		    kbdremap_state.rules[i].to);
	}
	mtx_unlock(&kbdremap_state.mtx);
	sbuf_finish(sb);

	if (sbuf_len(sb) >= sizeof(buf)) {
		sbuf_delete(sb);
		return (ENOMEM);
	}
	strlcpy(buf, sbuf_data(sb), sizeof(buf));
	error = sysctl_handle_string(oidp, buf, sizeof(buf), req);
	sbuf_delete(sb);
	if (error != 0)
		return (error);
	if (req->newptr == NULL)
		return 0; /* read only */

	new_count = 0;

	p = kbdremap_trim(buf);
	if (*p != '\0') { /* if empty jump to clearing */
		p = buf;
		while ((pair = strsep(&p, ",")) != NULL) {
			char *tp;
			if (*pair == '\0')
				continue;
			tp = kbdremap_trim(pair);
			if (*tp == '\0')
				continue;

			from_str = strsep(&tp, ":");
			to_str = tp;
			if (from_str == NULL || to_str == NULL) {
				printf("kbdremap: invalid rule format\n");
				return (EINVAL);
			}

			from_str = kbdremap_trim(from_str);
			to_str = kbdremap_trim(to_str);

			if (kbdremap_parse_hex(from_str, &from) != 0 ||
			    kbdremap_parse_hex(to_str, &to) != 0) {
				printf(
				    "kbdremap: invalid hex value in '%s:%s'\n",
				    from_str, to_str != NULL ? to_str : "");
				return (EINVAL);
			}

			if (seen[from]) {
				for (i = 0; i < new_count; i++) {
					if (new_rules[i].from == from) {
						new_rules[i].to = to;
						break;
					}
				}
				dup_warn = true;
				continue;
			}

			if (new_count >= KBDREMAP_MAX_RULES) {
				printf("kbdremap: too many rules (max %d)\n",
				    KBDREMAP_MAX_RULES);
				return (EINVAL);
			}

			new_rules[new_count].from = from;
			new_rules[new_count].to = to;
			seen[from] = true;
			new_count++;
		}
	}

	/* build map and apply rules */
	for (i = 0; i < 256; i++)
		new_map[i] = (uint8_t)i;
	for (i = 0; i < new_count; i++)
		new_map[new_rules[i].from] = new_rules[i].to;

	has_rules = (new_count > 0);

	mtx_lock(&kbdremap_state.mtx);
	/* update map and rules atomically */
	memcpy(kbdremap_state.map, new_map, sizeof(new_map));
	memcpy(kbdremap_state.rules, new_rules,
	    sizeof(struct kbdremap_rule) * new_count);
	kbdremap_state.count = new_count;
	/* publish active map token (or 0 if no rules) using integer atomic
	 * store */
	atomic_store_rel_long((volatile u_long *)&kbdremap_state.active_map_ptr,
	    (u_long)(uintptr_t)(has_rules ? kbdremap_state.map : NULL));
	mtx_unlock(&kbdremap_state.mtx);

	if (dup_warn)
		printf("kbdremap: duplicate 'from' entries (last wins)\n");

	printf("kbdremap: loaded %d remap rule%s\n", new_count,
	    new_count == 1 ? "" : "s");

	return (0);
}

SYSCTL_NODE(_hw, OID_AUTO, kbdremap, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Keyboard remapping");

SYSCTL_PROC(_hw_kbdremap, OID_AUTO, rules, CTLTYPE_STRING | CTLFLAG_RW, NULL, 0,
    sysctl_kbdremap_rules, "A", "Remap rules (format: 0xFROM:0xTO,...)");

static int
kbdremap_modevent(module_t mod, int type, void *data)
{
	int error = 0;

	switch (type) {
	case MOD_LOAD:
		for (int i = 0; i < 256; i++)
			kbdremap_state.map[i] = (uint8_t)i;

		kbdremap_state.count = 0;
		atomic_store_rel_long(
		    (volatile u_long *)&kbdremap_state.active_map_ptr,
		    (u_long)0);

		error = hidbus_register_kbd_remap_hook(kbdremap_get_map);
		if (error != 0) {
			printf("kbdremap: failed to register hook: %d\n",
			    error);
			return (error);
		}
		printf("kbdremap: keyboard remapping enabled\n");
		break;
	case MOD_UNLOAD:
		/* waits for in-flight callers to finish */
		hidbus_unregister_kbd_remap_hook(kbdremap_get_map);
		printf("kbdremap: keyboard remapping disabled\n");
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

static moduledata_t kbdremap_mod = { "kbdremap", kbdremap_modevent, NULL };

DECLARE_MODULE(kbdremap, kbdremap_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_VERSION(kbdremap, 1);
MODULE_DEPEND(kbdremap, hidbus, 1, 1, 1);
