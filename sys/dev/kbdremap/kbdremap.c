/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Toby Slight
 *
 * Kernel-level keyboard remapping for HID keyboards.
 * Remaps HID usage codes universally for all keyboard drivers.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/malloc.h>
#include <sys/sbuf.h>
#include <sys/lock.h>
#include <sys/mutex.h>

/* avoid including hidbus.h which has complex macros */
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

static uint32_t
kbdremap_translate(uint32_t usage)
{
	uint32_t result;
	int i;

	if (kbdremap_state.count == 0)
		return (usage);

	if (usage > 0xFF)
		return (usage);

	result = usage;

	mtx_lock(&kbdremap_state.mtx);
	for (i = 0; i < kbdremap_state.count; i++) {
		if (kbdremap_state.rules[i].from == usage) {
			result = kbdremap_state.rules[i].to;
			break;
		}
	}
	mtx_unlock(&kbdremap_state.mtx);

	return (result);
}

static int
sysctl_kbdremap_rules(SYSCTL_HANDLER_ARGS)
{
	char buf[1024];
	char current[1024];
	char *p, *pair, *from_str, *to_str;
	int error, i, new_count;
	struct kbdremap_rule new_rules[KBDREMAP_MAX_RULES];
	unsigned long from, to;
	
	current[0] = '\0';
	mtx_lock(&kbdremap_state.mtx);
	for (i = 0; i < kbdremap_state.count; i++) {
		if (i > 0)
			strlcat(current, ",", sizeof(current));
		snprintf(buf, sizeof(buf), "0x%02x:0x%02x",
		    kbdremap_state.rules[i].from,
		    kbdremap_state.rules[i].to);
		strlcat(current, buf, sizeof(current));
	}
	mtx_unlock(&kbdremap_state.mtx);
	
	/* current value to buf for sysctl_handle_string */
	strlcpy(buf, current, sizeof(buf));
	
	/* buf will be updated with new value user is setting */
	error = sysctl_handle_string(oidp, buf, sizeof(buf), req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	
	/* parse new rules */
	new_count = 0;
	p = buf;
	
	while ((pair = strsep(&p, ",")) != NULL) {
		if (*pair == '\0')
			continue;
		
		if (new_count >= KBDREMAP_MAX_RULES) {
			printf("kbdremap: too many rules (max %d)\n", 
			    KBDREMAP_MAX_RULES);
			break;
		}
		
		from_str = strsep(&pair, ":");
		to_str = pair;
		
		if (from_str == NULL || to_str == NULL) {
			printf("kbdremap: invalid rule format\n");
			continue;
		}
		
		from = strtoul(from_str, NULL, 0);
		to = strtoul(to_str, NULL, 0);
		
		if (from > 0xFF || to > 0xFF) {
			printf("kbdremap: out of range: 0x%lx:0x%lx (must be 0x00-0xFF)\n",
			    from, to);
			continue;
		}
		
		new_rules[new_count].from = (uint8_t)from;
		new_rules[new_count].to = (uint8_t)to;
		new_count++;
	}
	
	/* apply new rules atomically */
	mtx_lock(&kbdremap_state.mtx);
	memcpy(kbdremap_state.rules, new_rules,
	    sizeof(struct kbdremap_rule) * new_count);
	kbdremap_state.count = new_count;
	mtx_unlock(&kbdremap_state.mtx);
	
	printf("kbdremap: loaded %d remap rule%s\n", 
	    new_count, new_count == 1 ? "" : "s");
	
	return (0);
}

/* Sysctl tree */
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
