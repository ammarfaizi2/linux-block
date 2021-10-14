/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_API_EXE_FILE_H
#define _LINUX_MM_API_EXE_FILE_H

struct file;
struct mm_struct;
struct task_struct;

extern int set_mm_exe_file(struct mm_struct *mm, struct file *new_exe_file);
extern int replace_mm_exe_file(struct mm_struct *mm, struct file *new_exe_file);
extern struct file *get_mm_exe_file(struct mm_struct *mm);
extern struct file *get_task_exe_file(struct task_struct *task);

#endif /* _LINUX_MM_API_EXE_FILE_H */
