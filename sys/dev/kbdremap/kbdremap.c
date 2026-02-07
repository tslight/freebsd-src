/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Toby Slight
 *
 * Remaps HID usage codes for ukbd and hkbd
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/sbuf.h>
#include <sys/sysctl.h>

/* avoid including complex hidbus.h macros */
typedef uint32_t (*hidbus_kbd_remap_fn_t)(uint32_t);
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
	struct mtx mtx;
} kbdremap_state;

MTX_SYSINIT(kbdremap_mtx, &kbdremap_state.mtx, "kbdremap", MTX_DEF);

/* parse hex string into a uint8_t. */
static int
kbdremap_parse_hex(const char *s, uint8_t *out)
{
	unsigned int val;
	int i;

	if (s == NULL || *s == '\0')
		return (-1);

	/* skip optional "0x" or "0X" prefix */
	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
		s += 2;

	if (*s == '\0')
		return (-1);

	val = 0;
	for (i = 0; s[i] != '\0'; i++) {
		if (i >= 2) /* max 2 hex digits for uint8_t */
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

/* translate HID keyboard usage codes */
static uint32_t
kbdremap_translate(uint32_t usage)
{
	if (kbdremap_state.count == 0)
		return (usage);

	if (usage > 0xFF)
		return (usage);

	for (int i = 0; i < kbdremap_state.count; i++) {
		if (kbdremap_state.rules[i].from == (uint8_t)usage)
			return (kbdremap_state.rules[i].to);
	}

	return (usage);
}

static int
sysctl_kbdremap_rules(SYSCTL_HANDLER_ARGS)
{
	char buf[1024];
	char *p, *pair, *from_str, *to_str;
	int error, i, new_count;
	struct kbdremap_rule new_rules[KBDREMAP_MAX_RULES];
	uint8_t from, to;

	/* build current rules string */
	buf[0] = '\0';
	mtx_lock(&kbdremap_state.mtx);
	for (i = 0; i < kbdremap_state.count; i++) {
		char tmp[16];
		if (i > 0)
			strlcat(buf, ",", sizeof(buf));
		snprintf(tmp, sizeof(tmp), "0x%02x:0x%02x",
		    kbdremap_state.rules[i].from, kbdremap_state.rules[i].to);
		strlcat(buf, tmp, sizeof(buf));
	}
	mtx_unlock(&kbdremap_state.mtx);

	error = sysctl_handle_string(oidp, buf, sizeof(buf), req);
	if (error != 0 || req->newptr == NULL)
		return (error);

	/* parse new rules from buf */
	new_count = 0;
	p = buf;

	while ((pair = strsep(&p, ",")) != NULL) {
		if (*pair == '\0')
			continue;

		if (new_count >= KBDREMAP_MAX_RULES) {
			printf("kbdremap: too many rules (max %d)\n",
			    KBDREMAP_MAX_RULES);
			return (EINVAL);
		}

		from_str = strsep(&pair, ":");
		to_str = pair;

		if (from_str == NULL || to_str == NULL) {
			printf("kbdremap: invalid rule format\n");
			return (EINVAL);
		}

		if (kbdremap_parse_hex(from_str, &from) != 0 ||
		    kbdremap_parse_hex(to_str, &to) != 0) {
			printf("kbdremap: invalid hex value in '%s:%s'\n",
			    from_str, to_str != NULL ? to_str : "");
			return (EINVAL);
		}

		new_rules[new_count].from = from;
		new_rules[new_count].to = to;
		new_count++;
	}

	/* apply new rules atomically */
	mtx_lock(&kbdremap_state.mtx);
	kbdremap_state.count = 0;
	memcpy(kbdremap_state.rules, new_rules,
	    sizeof(struct kbdremap_rule) * new_count);
	kbdremap_state.count = new_count;
	mtx_unlock(&kbdremap_state.mtx);

	printf("kbdremap: loaded %d remap rule%s\n", new_count,
	    new_count == 1 ? "" : "s");

	return (0);
}

SYSCTL_NODE(_hw, OID_AUTO, kbdremap, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Keyboard remapping");

SYSCTL_PROC(_hw_kbdremap, OID_AUTO, rules,
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_NEEDGIANT, NULL, 0,
    sysctl_kbdremap_rules, "A", "Remap rules (format: 0xFROM:0xTO,...)");

static int
kbdremap_modevent(module_t mod, int type, void *data)
{
	int error = 0;

	switch (type) {
	case MOD_LOAD:
		kbdremap_state.count = 0;
		error = hidbus_register_kbd_remap_hook(kbdremap_translate);
		if (error != 0) {
			printf("kbdremap: failed to register hook: %d\n",
			    error);
			return (error);
		}
		printf("kbdremap: keyboard remapping enabled\n");
		break;

	case MOD_UNLOAD:
		hidbus_unregister_kbd_remap_hook(kbdremap_translate);
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
