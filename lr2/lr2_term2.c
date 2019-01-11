#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/cred.h>
#include <linux/string.h>

#define DEVICE_NAME "lr2_term2"
#define READER 32768
#define WRITER 32769

static int buf_len = 10;
module_param(buf_len, int , 0);

static int major_num;

LIST_HEAD(users_context_list);
DEFINE_MUTEX(open_lock);
DECLARE_WAIT_QUEUE_HEAD(wq);

struct context {
	kuid_t uid;
	char *msg_buffer;
	int buf_len;
	char *read_ptr;
	char *write_ptr;
	struct mutex *read_lock;
	struct mutex *write_lock;
	struct mutex *lock;
	bool full;
	bool empty;
};

struct users_context_el {
	struct context *user_context;
	struct list_head node;
};

static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char __user *, size_t, loff_t *);
static long device_ioctl(struct file *f, unsigned int cmd, unsigned long arg);

static struct file_operations file_ops = {
	.read = device_read,
	.write = device_write,
	.unlocked_ioctl = device_ioctl,
	.open = device_open,
	.release = device_release
};

struct aval_space {
	int from_cur;
	int from_start;
};

static struct aval_space calc_space(struct context *user, char *ptr) {
	char *ptr_inverse;
	struct aval_space result;
	bool flag = false;

	if (ptr == user->write_ptr) {
		ptr_inverse = user->read_ptr;
	} else {
		ptr_inverse = user->write_ptr;
	}
	while (ptr != ptr_inverse) {
		if (flag) {
			result.from_start++;
		} else {
			result.from_cur++;
		}
		++ptr;
		if (ptr == user->msg_buffer + user->buf_len) {
			ptr = user->msg_buffer;
			flag = true;
		}
	}
	if (user->empty || user->full) {
		result.from_cur = user->buf_len;
		result.from_start = 0;
	}
	return result;
}

static ssize_t device_read(struct file *file, char __user *buffer, size_t len, loff_t *offset) {
	struct context *user = (struct context *)file->private_data;
	struct aval_space space;
	int bytes_read = 0;

	printk(KERN_INFO "IN READ!\n");
	mutex_lock_interruptible(user->lock);
	while (len) {		
		if (user->empty) {
			mutex_unlock(user->lock);
			printk(KERN_INFO "SLEEP IN READ, MUTEX: %d!\n", mutex_is_locked(user->lock));
			wait_event_interruptible(wq, user->empty == false);
			mutex_lock_interruptible(user->lock);
		}
		space = calc_space(user, user->read_ptr);
		if (copy_to_user(buffer + bytes_read, user->read_ptr, space.from_cur)) {
			goto errCopy;
		}
		bytes_read += space.from_cur;
		if (copy_to_user(buffer + bytes_read, user->msg_buffer, space.from_start)) {
			goto errCopy;
		}
		bytes_read += space.from_start;
		if (space.from_start) {
			user->read_ptr = user->msg_buffer + space.from_start;
		} else {
			user->read_ptr += space.from_cur;
		}
		if (user->read_ptr == user->msg_buffer + user->buf_len) {
			user->read_ptr = user->msg_buffer;
		}
		if (user->read_ptr == user->write_ptr) {
			user->empty = true;
		}
		user->full = false;
		len -= space.from_cur + space.from_start;
		wake_up_interruptible(&wq);		
	}
	mutex_unlock(user->lock);
	return bytes_read;
errCopy:
	printk(KERN_ERR "Error! Unable to copy from userspace!\n");
	mutex_unlock(user->lock);
	return -1;
}
	

static ssize_t device_write(struct file *file, const char __user *buffer, size_t len, loff_t *offset) {
	struct context *user = (struct context *)file->private_data;
	struct aval_space space;
	int bytes_write = 0;

	printk(KERN_INFO "IN WRITE!\n");
	mutex_lock_interruptible(user->lock);
	while (len) {		
		if (user->full) {
			mutex_unlock(user->lock);
			printk(KERN_INFO "SLEEP IN WRITE, MUTEX: %d!\n", mutex_is_locked(user->lock));
			wait_event_interruptible(wq, user->full == false);
			mutex_lock_interruptible(user->lock);
		}
		space = calc_space(user, user->write_ptr);
		//printk(KERN_INFO "SPACE do konca: %d\tot nachala: %d\n", space.from_cur, space.from_start);
		if (copy_from_user(user->write_ptr, buffer + bytes_write, space.from_cur)) {
			goto errCopy;
		}
		bytes_write += space.from_cur;
		if (copy_from_user(user->msg_buffer, buffer + bytes_write, space.from_start)) {
			goto errCopy;
		}
		bytes_write += space.from_start;
		if (space.from_start) {
			user->write_ptr = user->msg_buffer + space.from_start;
		} else {
			user->write_ptr += space.from_cur;
		}
		if (user->write_ptr == user->msg_buffer + user->buf_len) {
			user->write_ptr = user->msg_buffer;
		}
		if (user->write_ptr == user->read_ptr) {
			user->full = true;
		}
		user->empty = false;
		len -= space.from_cur + space.from_start;
		wake_up_interruptible(&wq);		
	}
	mutex_unlock(user->lock);
	return bytes_write;
errCopy:
	printk(KERN_ERR "Error! Unable to copy from userspace!\n");
	mutex_unlock(user->lock);
	return -1;
}

static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
	struct context *user = (struct context *)file->private_data;
	char *new_msg_buf;
	struct aval_space space;

	mutex_lock_interruptible(user->lock);
	// Размер буфера не изменяется
	if (arg == user->buf_len) {
		printk(KERN_ALERT "new buffer size is %d\n", buf_len);
		mutex_unlock(user->lock);
		return 0;
	}
	// Проверка допустимого значения размера буфера
	if ((arg < 1) || (arg > 100) || (arg < buf_len)) {
		printk(KERN_ERR "Error! The size hasn`t been changed!\n");
		printk(KERN_ERR "Invalid size of buffer: %ld\n", arg);
		mutex_unlock(user->lock);
		return -1;	
	}
	new_msg_buf = (char *)kcalloc(arg + 1, sizeof(char), GFP_KERNEL);
	if (new_msg_buf == NULL) {
		printk(KERN_ERR "Error! The size hasn`t been changed!\n");
		printk(KERN_ERR "Error! Unable to allocate memory!\n");
		mutex_unlock(user->lock);
		return -1;
	}
	if (user->empty) {
		user->write_ptr = new_msg_buf;
	} else {
		space = calc_space(user, user->read_ptr);
		strncpy(new_msg_buf, user->read_ptr, space.from_start + space.from_cur);
		user->write_ptr = new_msg_buf + space.from_start + space.from_cur;
	}
	user->msg_buffer = new_msg_buf;
	user->read_ptr = new_msg_buf;
	user->buf_len = arg;
	mutex_unlock(user->lock);
	return 0;
}

static struct context* find_cont_of_user(kuid_t uid) {
	struct users_context_el *cursor;
	list_for_each_entry(cursor, &users_context_list, node) {
		if ((cursor->user_context->uid).val == uid.val) {
			return cursor->user_context;
		}
	}
	return NULL;
}

static int device_open(struct inode *inode, struct file *file) {
	struct context *user;
	struct users_context_el *new_user;
	kuid_t user_id = current_uid();

	mutex_lock_killable(&open_lock);
	// Проверка: имеет ли данный пользователь буфер
	user = find_cont_of_user(user_id);
	if (user == NULL) {
		// Создание буфера для пользователя
		user = kzalloc(sizeof(struct context), GFP_KERNEL);
		if (user == NULL) {
			goto errAlloc;
		}
		user->uid = user_id;
		user->msg_buffer = (char *)kcalloc(buf_len + 1, sizeof(char), GFP_KERNEL);
		if (user->msg_buffer == NULL) {
			goto errAlloc;
		}
		user->read_lock = kzalloc(sizeof(struct mutex), GFP_KERNEL);
		if (user->read_lock == NULL) {
			goto errAlloc;
		}
		mutex_init(user->read_lock);
		user->write_lock = kzalloc(sizeof(struct mutex), GFP_KERNEL);
		if (user->write_lock == NULL) {
			goto errAlloc;
		}
		mutex_init(user->write_lock);
		user->lock = kzalloc(sizeof(struct mutex), GFP_KERNEL);
		if (user->lock == NULL) {
			goto errAlloc;
		}
		mutex_init(user->lock);

		user->msg_buffer[buf_len] = '\0';
		user->buf_len = buf_len;
		user->read_ptr = user->msg_buffer;
		user->write_ptr = user->msg_buffer;
		user->empty = true;
		user->full = false;
		
		new_user = kzalloc(sizeof(struct users_context_el), GFP_KERNEL);
		if (new_user == NULL) {
			goto errAlloc;
		}
		new_user->user_context = user;
		list_add_tail(&new_user->node, &users_context_list);
	}
	mutex_unlock(&open_lock);
	// Печенька
	file->private_data = (void *)user;
	// Файлы могут быть только для чтения или только для записи
	// Процесс-чтец может получить доступ к буферу
	// только после освобождения мьютекса предыдущим чтецом
	switch (file->f_flags) {
		case READER:
			mutex_lock_interruptible(user->read_lock);
			break;
		case WRITER:
			mutex_lock_interruptible(user->write_lock);
			break;
		default:
			printk(KERN_ERR "Error! File flags: O_WRONLY or O_RDONLY!\n");
			return -1;
	}
 	try_module_get(THIS_MODULE);
	return 0;
errAlloc:
	printk(KERN_ERR "Error! Unable to allocate memory!\n");
	mutex_unlock(&open_lock);
	return -1;
}

static int device_release(struct inode *inode, struct file *file) {
	struct context *user = (struct context *)file->private_data;
	// Освобождение мьютекса на запись/чтение
	switch (file->f_flags) {
		case READER:
			mutex_unlock(user->read_lock);
			break;
		case WRITER:
			mutex_unlock(user->write_lock);
			break;
	}
 	module_put(THIS_MODULE);
 	return 0;
}

static int __init lr2_term2_init(void) {
	// Проверка допустимого значения размера буфера
	if ((buf_len < 1) || (buf_len > 100)) {
		printk(KERN_INFO "Error! Invalid size of buffer: %d\n", buf_len);
		return -1;	
	}
	 	
 	major_num = register_chrdev(0, "lr2_term2", &file_ops);
 	if (major_num < 0) {
 		printk(KERN_INFO "Could not register device: %d\n", major_num);
 		return major_num;
 	} else {
 		printk(KERN_ALERT "lr2_term2 module loaded with device major number %d\n", major_num);
		printk(KERN_INFO "buffer size is %d\n", buf_len);
 		return 0;
 	}
}

static void __exit lr2_term2_exit(void) {
	// Удаление списка буферов пользователей
	struct users_context_el *cursor;
	struct list_head *iter, *iter_safe;
	list_for_each_safe(iter, iter_safe, &users_context_list) {
      cursor = list_entry(iter, struct users_context_el, node);
      list_del(iter);
      kfree(cursor);
   	}
	unregister_chrdev(major_num, DEVICE_NAME);
 	printk(KERN_ALERT "lr2_term2 module was removed from the kernel!\n");
}

module_init(lr2_term2_init);
module_exit(lr2_term2_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fursov Aleksandr");
MODULE_DESCRIPTION("Lr2_term2");
MODULE_VERSION("0.01");

/*
	kfree(msg_buffer);
	buf_len = arg;
	msg_buffer = (char *)kcalloc(buf_len, sizeof(char), GFP_KERNEL);
	if (msg_buffer == NULL) {
		printk(KERN_ERR "Error! Unable to allocate memory!\n");
		return -1;
	}
		msg_buffer[buf_len] = '\0';
	
		read_ptr = msg_buffer;
	write_ptr = msg_buffer;
	empty = true;
	full = false;
	printk(KERN_INFO "Size of buffer has been changed: %d\n", buf_len);
*/