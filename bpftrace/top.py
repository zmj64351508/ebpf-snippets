import subprocess, time

if __name__ == "__main__":
	subprocess.call(['rm', '/sys/fs/bpf/task_time', '-f'])
	subprocess.call(['bpftrace', '-e', r'iter:task:task_time { printf("%u %u %llu %llu %s\n", ctx->task->tgid, ctx->task->pid, ctx->task->utime, ctx->task->stime, ctx->task->comm) }'])

	first_time = True
	time_start_interval = {}
	time_in_interval = {}
	interval = 3
	while True:
		with open("/sys/fs/bpf/task_time", "r") as f:
			for line in f.readlines():
				split_line = line.split()
				tgid = int(split_line[0])
				pid = int(split_line[1])
				utime = int(split_line[2])
				stime = int(split_line[3])
				try:
					comm = split_line[4]
				except Exception:
					comm = ""

				if not first_time:
					if pid not in time_start_interval:
						time_start_interval[pid] = [0, 0]
					time_in_interval[pid] = [utime - time_start_interval[pid][0], stime - time_start_interval[pid][1], tgid, comm]

				# update start time for next interval
				time_start_interval[pid] = [utime, stime]

		if first_time:
			first_time = False
			time.sleep(interval)
			continue

		print("PID\tTID\t%CPU\t%UTIME\t%STIME\tCOMM")
		i = 0
		for key, value in sorted(time_in_interval.items(), reverse=True, key=lambda item: item[1][0]+item[1][1]):
			if i < 20 and (value[0] > 0 or value[1] > 0):
				utime_percent = value[0] / 1e9 * 100 / interval
				stime_percent = value[1] / 1e9 * 100 / interval
				total_percent = utime_percent + stime_percent
				tgid = value[2]
				comm = value[3]
				print("%u\t%u\t%.1f\t %.1f\t%.1f\t%s" % (tgid, key, total_percent, utime_percent, stime_percent, comm))
				i += 1
		print("")

		time_in_interval.clear()
		time.sleep(interval)