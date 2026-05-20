#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
    struct seq_file *seq = ctx->meta->seq;
    struct task_struct *task = ctx->task;

    if (task == NULL)
        return 0;

    /* Print PID (tgid) and command name separated by tab */
    bpf_seq_printf(seq, "%d\t%s\n", task->tgid, task->comm);

    return 0;
}
