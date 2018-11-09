#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

static char *whom = "world";
module_param(whom, charp, 0);

static int __init lkm_example_init(void) {
	printk(KERN_INFO "Hello, %s!\n", whom);
 	return 0;
}

static void __exit lkm_example_exit(void) {
 	printk(KERN_INFO "Goodbye, %s!\n", whom);
}

module_init(lkm_example_init);
module_exit(lkm_example_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aleksandr Fursov");
MODULE_DESCRIPTION("A simple Linux module.");
MODULE_VERSION("0.01");
//objdump посмотреть про бинарник






















