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
        except ValueError:
            msg = "Coulnd't get namespace for container %"
            logging.exception(msg, args.container)
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


traditional = [
    (1024 ** 5, 'P'),
    (1024 ** 4, 'T'),
    (1024 ** 3, 'G'),
    (1024 ** 2, 'M'),
    (1024 ** 1, 'K'),
    (1024 ** 0, 'B'),
    ]


def size(size_in_bytes, system=None):
    """Human-readable file size.

    Using the traditional system, where a factor of 1024 is used::

    >>> size(10)
    '10B'
    >>> size(100)
    '100B'
    >>> size(1000)
    '1000B'
    >>> size(2000)
    '1K'
    >>> size(10000)
    '9K'
    >>> size(20000)
    '19K'
    >>> size(100000)
    '97K'
    >>> size(200000)
    '195K'
    >>> size(1000000)
    '976K'
    >>> size(2000000)
    '1M'

    Using the SI system, with a factor 1000::

    >>> size(10, system=si)
    '10B'
    >>> size(100, system=si)
    '100B'
    >>> size(1000, system=si)
    '1K'
    >>> size(2000, system=si)
    '2K'
    >>> size(10000, system=si)
    '10K'
    >>> size(20000, system=si)
    '20K'
    >>> size(100000, system=si)
    '100K'
    >>> size(200000, system=si)
    '200K'
    >>> size(1000000, system=si)
    '1M'
    >>> size(2000000, system=si)
    '2M'

    """
    system = system or traditional

    for factor, suffix in system:
        if size_in_bytes >= factor:
            break
    amount = int(size_in_bytes/factor)
    if isinstance(suffix, tuple):
        singular, multiple = suffix
        if amount == 1:
            suffix = singular
        else:
            suffix = multiple
    return str(amount) + suffix
