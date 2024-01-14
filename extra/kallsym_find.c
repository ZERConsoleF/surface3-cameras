#include <linux/kallsyms.h>
#include <linux/kprobes.h>

#include "atomisp.h"

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

unsigned long (*kallsyms_lookup_name_t)(const char *name);

static int (*kallsym_efivar_entry_get)(struct efivar_entry *entry, u32 *attributes, unsigned long *size, void *data) = NULL;

unsigned long kallsyms_lookup_name_f(const char *name)
{
    if (!kallsyms_lookup_name_t)
    {
        register_kprobe(&kp);
        kallsyms_lookup_name_t = (unsigned long)kp.addr;
        unregister_kprobe(&kp);
    }
    if (!kallsyms_lookup_name_t)
    {
        printk(KERN_ERR "kprobe: kallsyms_lookup_name could not load!\n");
        return 0;
    }
    return kallsyms_lookup_name_t(name);
}

int efivar_entry_get(struct efivar_entry *entry, u32 *attributes, unsigned long *size, void *data)
{
	if (!kallsym_efivar_entry_get)
	{
		kallsym_efivar_entry_get = kallsyms_lookup_name_f("efivar_entry_get");
		if (!kallsym_efivar_entry_get)
		{
			printk(KERN_ERR "efivar_entry_get link to kallsym_efivar_entry_get: Symbol not found!");
			return 0;
		}
	}
	return kallsym_efivar_entry_get(entry, attributes, size, data);
}
