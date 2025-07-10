import subprocess


def alive(ip):
    """
    Test if a host is reachable.
    Returns True if the host is reachable, False otherwise.
    """
    command = ["fping", ip]
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    return result.returncode == 0


# @shared_task
# def ping_hosts():
#     """
#     Fetch all hosts from the DB, ping each one,
#     and record the result in the PingResult model.
#     """
#     hosts = Host.objects.all()
#     for host in hosts:
#         status = alive(host.ip_address)
#         # Create a new PingResult (timestamp is set automatically)
#         Ping.objects.create(host=host, is_alive=status)
