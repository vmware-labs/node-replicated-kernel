#!/bin/env python

# Copyright © Adam Zegelin (https://github.com/zegelin/qemu-affinity).
# SPDX-License-Identifier: MIT

import argparse
from pathlib import Path
import re
import itertools
from operator import itemgetter
from collections import Counter, OrderedDict, namedtuple
import os

QEMU_COMM_RE = re.compile('qemu-system-.+$')
QEMU_DEBUG_RE = re.compile('debug-threads=on')
AFFINITY_SPEC_RE = re.compile('(\d+)(?:-(\d+))?$')

ALL_THREADS = object()

QemuProc = namedtuple('QemuProc', ['pid', 'exe', 'cmdline', 'main_thread', 'threads'])
QemuThread = namedtuple('QemuThread', ['tid', 'name'])

def qemu_proc(pid):
	# readdir(/proc) only lists TGIDs (aka true PIDs)
	# but stat(/proc/TID) will work.
	# There appears to be no easy way to determine if a /proc
	# entry is a thread or process (thread-group) except
	# to check if the ID isn't returned by readdir(...)
	
	if os.getuid() != 0:
		raise argparse.ArgumentTypeError('must be root to manipulate PID %s' % pid)
	
	pid = int(pid)
	
	procs = list(filter(lambda p: p.name == str(pid), Path('/proc').iterdir()))

	if len(procs) == 0:
		raise argparse.ArgumentTypeError('pid %s does not exist.' % pid)
		
	p = procs[0]
	
	exe = (p / 'exe').resolve()
	if not QEMU_COMM_RE.match(exe.name):
		raise argparse.ArgumentTypeError('pid %s is not a qemu-system process.' % pid)
		
	cmdline = (p / 'cmdline').read_text().split('\0')
	
	if len(list(filter(QEMU_DEBUG_RE.search, cmdline))) == 0:
		raise argparse.ArgumentTypeError('qemu debug thread naming disabled. add \'-name <name>,debug-threads=on\' to the qemu command line.')
		
	def qemu_thread(task):
		id = int(task.name)
		comm = (task / 'comm').read_text().strip()
		
		return (id, QemuThread(id, comm))
		
	tasks = p.glob('task/*')
	tasks = OrderedDict(map(qemu_thread, tasks))
	main_thread = tasks.pop(pid) # remove main PID/TGID from tasks
	
	return QemuProc(pid, exe, cmdline, main_thread, tasks)

"""a thread selector, or '*' meaning ALL_THREADS"""
def thread_selector(tsel):
	if tsel is None:
		return None
	
	tsel = tsel.strip()
	
	if tsel == '*':
		return ALL_THREADS
	
	return tsel

""""0-3,4,5" -> {0, 1, 2, 3, 4, 5}"""
def affinity(afspec):
	try:
		af = map(lambda s: AFFINITY_SPEC_RE.match(s).groups(), afspec.split(','))
		af = map(lambda m: list(map(int, filter(None, m))), af)
		af = map(lambda r: range(r[0], r[1] + 1) if len(r) == 2 else r, af)
		
		return set(itertools.chain(*af))
		
	except AttributeError:
		raise argparse.ArgumentError()
		
ThreadAffinity = namedtuple('ThreadAffinity', ['selector', 'affinity'])

"""thread id + affinity"""
class ThreadAffinityType:
	def __init__(self, allow_thread_names=True):
		self.allow_thread_names = allow_thread_names
		
	def __call__(self, string):
		# str -> [None, afspec] 
		# str : str -> [tsel, afspec]
		sel, afspec = (lambda default, spec: default[len(spec):]+spec)([None, None], string.split(':'))
		
		sel = thread_selector(sel)
		
		if not self.allow_thread_names and isinstance(sel, str):
			raise argparse.ArgumentTypeError('thread names not allowed.')
		
		return ThreadAffinity(sel, affinity(afspec))

	def __repr__(self):
		return 'THREAD_AFFINITY'
	

PositionalThreadSelector = namedtuple('PositionalThreadSelector', ['position'])

class ThreadAffinityAction(argparse.Action):
	def __call__(self, parser, namespace, values, option_string=None):
		positional_values = filter(lambda v: v.selector is None, values)
		positional_values = map(lambda v: ThreadAffinity(PositionalThreadSelector(v[0]), v[1].affinity), enumerate(positional_values))
		
		values = filter(lambda v: v.selector is not None, values)
		values = list(itertools.chain(values, positional_values))

		# counter over selectors
		selectors = Counter(filter(None, map(lambda v: v.selector, values)))
		
		# prevent duplicate tids
		if len(list(filter(lambda c: c > 1, selectors.values()))) > 0:
			parser.error('argument %s: duplicate affinity value.' % argparse._get_action_name(self))
		
		setattr(namespace, self.dest, dict(values))

def main():

	parser = argparse.ArgumentParser(description='Set QEMU thread affinity',
	formatter_class=argparse.RawDescriptionHelpFormatter,
	epilog="""
	THREAD_AFFINITY can be one of:
		<affinity-spec>
		<selector>:<affinity-spec>
		
		Where <affinity-spec> is:
			a CPU number, a range (inclusive) of CPU numbers separated by a 
			dash (-), or a comma-delimited (,) list of CPU numbers or
			ranges.
			
			for example:
				0\t\tspecifies CPU 0
				0,1,2,3\t\tspecifies CPU 0, 1, 2 and 3
				0-3\t\tsame as above
				0,2-4,6\t\tspecifies CPU 0, 2, 3, 4 and 6
			

		Where <selector> is:
			*\t\t\tall threads (for -k, -i, -w, -t)
			<partial-name>\t\tfor -k ('CPU <partial-name>/KVM')
			              \t\tand -i ('IO <partial-name>')
			<name>\t\t\tfor -t
		
		The first variant selects threads based on argument position.
		e.g.,   -k 0,4 1,5 2,6 3,7   pins the first KVM thread to CPUs 0 and 4,
		the second KVM thread to CPUs 1 and 5, and so on.
		
		The second variant selects threads by <selector>, which is a partial 
		name or wildcard. KVM threads have numeric names ('0', '1', '2', etc).
		IO threads have user-supplied names (`-object iothread,id=<name>`).
		e.g.,   -k 2:2,6 -i myiothread:7 *:0   pins KVM thread 2 to CPUs 2 and
		6, IO thread 'myiothread' to CPU 7, and all remaining IO threads to
		CPU 0.
		
		The two variants can be combined.
		e.g.,   -k 0,4 *:2,6   pins the first KVM thread to CPUs 0 and 4,
		and all remaining KVM threads to CPUs 2 and 6.

	""")
	parser.add_argument('qemu_proc', type=qemu_proc, metavar='[--] qemu-system-pid', help='PID of the qemu-system process')
	parser.add_argument('--dry-run', action='store_true', help='don\'t modify thread affinity values (useful with -v)')
	parser.add_argument('-v', '--verbose', action='store_true', help='be verbose (always output current thread affinity values and modifications)')
	parser.add_argument('-p', '--process-affinity', nargs='?', type=affinity, metavar='AFFINITY', help='set \'qemu-system\' process affinity (and default for new threads)')
	parser.add_argument('-q', '--qemu-affinity', nargs='+', action=ThreadAffinityAction, type=ThreadAffinityType(allow_thread_names=False), metavar='AFFINITY', help='set \'qemu-system\' thread affinity (partial name selectors not allowed)')
	parser.add_argument('-k', '--kvm-affinity', nargs='+', action=ThreadAffinityAction, type=ThreadAffinityType(), metavar='THREAD_AFFINITY', help='set KVM (\'CPU <n>/KVM\') thread affinity')
	parser.add_argument('-i', '--io-affinity', nargs='+', action=ThreadAffinityAction, type=ThreadAffinityType(), metavar='THREAD_AFFINITY', help='set IO object (\'IO <name>\') thread affinity')
	parser.add_argument('-w', '--worker-affinity', nargs='+', action=ThreadAffinityAction, type=ThreadAffinityType(allow_thread_names=False), metavar='THREAD_AFFINITY', help='set qemu worker (\'worker\') thread affinity (partial name selectors not allowed)')
	parser.add_argument('-t', '--thread-affinity', nargs='+', action=ThreadAffinityAction, type=ThreadAffinityType(), metavar='THREAD_AFFINITY', help='set arbitary (\'<name>\') thread affinity')

	def get_argument(name):
		# yuck, why isn't this public
		return parser._option_string_actions[name]

	args = parser.parse_args()

	def cores_affinityspec(cores):
		# [(k, [(0, x), (1, y) (2, z)]), (j, [(0, a), (1, b) (2, c)])]
		spec_groups = itertools.groupby(enumerate(cores), lambda e: e[0]-e[1])
		spec_groups = [list(map(itemgetter(1), g)) for k, g in spec_groups]
		spec_groups = ','.join(['%s-%s' % (g[0], g[-1]) if len(g) > 1 else str(g[0]) for g in spec_groups])
			
		return spec_groups
			
	classes = [
		# [argument, thread name regex, thread name format]
		['--qemu-affinity', re.compile('^qemu-system-.*$'), None],
		['--kvm-affinity', re.compile('^CPU (?P<name>\d+)/KVM$'), 'CPU %s/KVM'],
		['--io-affinity', re.compile('^IO (?P<name>.+)$'), 'IO %s'],
		['--worker-affinity', re.compile('^worker$'), None],
		['--thread-affinity', re.compile('^(?P<name>.+)$'), '%s']
	]

	thread_affinities = OrderedDict()

	if args.process_affinity is not None:
		thread_affinities[args.qemu_proc.main_thread] = args.process_affinity

	for (arg, thread_name_re, thread_name_fmt) in classes:
		arg = get_argument(arg)

		affinities = vars(args)[arg.dest]
		
		if affinities is None:
			continue;
			
		spec_count = len(affinities)
		
		# [thread] -> [(thread, match)]
		threads = map(lambda t: (t, thread_name_re.match(t.name)), args.qemu_proc.threads.values())
		threads = filter(lambda v: v[1] is not None, threads)
		
		for (i, (thread, match)) in enumerate(threads):
			default_affinity = affinities.get(ALL_THREADS)
			positional_affinity = affinities.pop(PositionalThreadSelector(i), None)
			named_affinity = affinities.pop(match.groupdict().get('name'), None)
			
			aff = named_affinity or positional_affinity or default_affinity
			
			if aff is None:
				continue
			
			thread_affinities[thread] = aff
		
		affinities.pop(ALL_THREADS, None)
		
		if len(affinities) != 0:
			selector = affinities.popitem()[0]
			
			if isinstance(selector, PositionalThreadSelector):
				parser.error('argument %s: too many positional affinity specifications (%d threads, %d provided).' % (argparse._get_action_name(arg), len(threads), spec_count))
				
			tname = thread_name_fmt % selector
			parser.error('argument %s: thread id {%s} not found.' % (argparse._get_action_name(arg), tname))
	
	if len(thread_affinities) == 0 or args.verbose:
		print('%s(%d) threads:' % (args.qemu_proc.exe.name, args.qemu_proc.pid))
		for thread in args.qemu_proc.threads.values():
			print('\t{%s}(%d): %s' % (thread.name, thread.tid, cores_affinityspec(os.sched_getaffinity(thread.tid))))
	
	if len(thread_affinities) == 0:
		parser.exit(-1)
			
	if args.verbose or args.dry_run:
		print('%s %s(%d) thread affinities to:' % ('Would set' if args.dry_run else 'Setting', args.qemu_proc.exe.name, args.qemu_proc.pid))
		for (thread, aff) in thread_affinities.items():
			print('\t{%s}(%d): %s' % (thread.name, thread.tid, cores_affinityspec(aff)))
			
	if args.dry_run:
		exit(-1)
		
	for (thread, aff) in thread_affinities.items():
		os.sched_setaffinity(thread.tid, aff)
		
if __name__ == '__main__':
	main()
