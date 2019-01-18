import os
import logging


DOCKER_PID_CMD = "docker inspect {} --format='{{{{.State.Pid}}}}'"
NSS_CMD = "lsns -p {} -t pid | tail -n 1 | awk '{{print $1}}'"


def replace_namespace(text, args):
    nss = None

    text = text.replace("SAVE_NAMESPACE", """
    struct task_struct *t = (struct task_struct *) bpf_get_current_task();
    key.namespace = t->nsproxy->pid_ns_for_children->ns.inum;
    """)

    if args.container:
        try:
            pid_response = os.popen(DOCKER_PID_CMD.format(args.container))
            pid = int(pid_response.read().strip())
            nss_response = os.popen(NSS_CMD.format(pid))
            nss = int(nss_response.read().strip())
        except ValueError as ex:
            msg = "Coulnd't get namespace for container {}"
            logging.exception(msg.format(args.container))
            nss = None

    if args.namespace and not nss:
        nss = args.namespace

    if not nss:
        text = text.replace("CHECK_NAMESPACE", "")
        return text

    # starting from 4.18 it's possible to use cgroup_id:
    # key->cgroup_id = bpf_get_current_cgroup_id();

    text = text.replace("CHECK_NAMESPACE", """
    if (key.namespace != {})
        return 0;
    """.format(nss))
    return text
