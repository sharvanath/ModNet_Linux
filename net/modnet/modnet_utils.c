/* The ModNet utility functions
 * Author: Sharvanath Pathak */
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fsnotify.h>
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/namei.h>
#include <linux/backing-dev.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <linux/security.h>
#include <linux/mount.h>
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/fs.h>
#include <linux/personality.h>
#include <linux/pagemap.h>
#include <linux/syscalls.h>
#include <linux/rcupdate.h>
#include <linux/audit.h>
#include <linux/falloc.h>
#include <linux/fs_struct.h>
#include <linux/ima.h>
#include <linux/dnotify.h>
#include <linux/compat.h>

void fd_install_custom(unsigned int fd, struct file *file)
{
	struct files_struct *files = current->files;
	struct fdtable *fdt;
	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	rcu_assign_pointer(fdt->fd[fd], file);
	spin_unlock(&files->file_lock);
}
EXPORT_SYMBOL(fd_install_custom);

int fd_swap_custom(int original_fd, struct file *file, struct file *file_new, struct task_struct * task_ptr)
{
	struct files_struct *files = task_ptr->files;
	struct fdtable *fdt;
	int i=0;
	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);

	for(i=0;i<fdt->max_fds;i++)
	{
		 if(fd_is_open(i, fdt) && rcu_access_pointer(fdt->fd[i]) == file)
		 {
			 rcu_assign_pointer(fdt->fd[i], file_new);
			 spin_unlock(&files->file_lock);
			 return 1;
		 }
	}
	fd_install_custom(original_fd, file);
	spin_unlock(&files->file_lock);
	return 0;
}
EXPORT_SYMBOL(fd_swap_custom);