###Author: Shivam Verma###

import sys
import re
from datetime import timedelta
from datetime import datetime
from operator import itemgetter, attrgetter

def run_feature1(out1_path, inp_list):
    """
    Feature 1: List in descending order of the top 10 most active hosts/IP addresses that have accessed the site.
    """
    hosts = {} #looks like {host1: count1, ...}
    for inp in inp_list: #for each request
        try:
            if hosts[inp[0]]:
                hosts[inp[0]] += 1 #update host-count dictionary
        except KeyError:
            hosts[inp[0]] = 1

    #lexicographic sort by host counts
    sorted_hosts = sorted(hosts.items(), key=lambda x: (-x[1],x[0]))
    #key=lambda x: x[1], reverse=True)

    with open(out1_path,'wb') as f:
        for i in range(10):
            try:
                f.write(sorted_hosts[i][0]+","+str(sorted_hosts[i][1])+"\n")
            except IndexError:
                pass



def run_feature2(out2_path, inp_list):
    """
    Feature 2: Identify the top 10 resources on the site that consume the most bandwidth.
    """

    resources = {} #looks like {resource1: bandwidth1, ...}
    for inp in inp_list: #for each request
        try:
            res = inp[2].split(" ")[1] #get resource from request
        except IndexError:
            print "faulty input: ",inp
            res = inp[2].split(" ")[0] #resource not present
        byte = int(inp[-1])
        try:
            if resources[res]:
                resources[res] += byte #update resource-bandwidth dictionary
        except KeyError:
            resources[res] = byte

    #lexicographic sort by bandwidth
    sorted_resources = sorted(resources.items(), key=lambda x: (-x[1],x[0]))

    with open(out2_path,'wb') as f:
        for i in range(10):
            try:
                f.write(sorted_resources[i][0]+"\n")
            except IndexError:
                pass

def convert_to_datetime(ts):
    """
    Converts timestamp string to datetime object.
    """
    formats = ['%d/%b/%Y:%H:%M:%S','%d/%b/%Y:%H:%M', '%d/%b/%Y:%H', '%d/%b/%Y']
    ts = ts.split(" ")[0].rstrip(":") #remove timezone
    out = datetime(1111, 1, 1, 0, 0, 0) #default time if nothing works
    for f in formats:
        try:
            t = datetime.strptime(ts, f)
            out = datetime(t.year, t.month, t.day, t.hour, t.minute, t.second) #make sure HH:MM:SS is present
            break
        except ValueError:
            continue
    return out


def run_feature3(out3_path, inp_list):
    """
    Feature 3: Identify the top 10 resources on the site that consume the most bandwidth.
    """

    timestamps = map(lambda x: convert_to_datetime(x[1]), inp_list) #remove timezone, get list
    sorted_timestamps = sorted(timestamps) #sort by timestamp in increasing order

    start_times = {} #looks like {time1: count1 ...}
    curr_time = sorted_timestamps[0]
    end_time = sorted_timestamps[-1]

    while curr_time < end_time: #for each start time

        if curr_time not in start_times:
            start_times[curr_time] = 0

        cutoff = curr_time + timedelta(minutes=60) #60-min. cutoff for curr_time

        for x in sorted_timestamps: #for each sorted timestamp
            if x >= curr_time:
                if x <= cutoff: #if below cutoff
                    start_times[curr_time] += 1 #update time-count dictionary
                else:
                    break
            else:
                continue

        curr_time = curr_time + timedelta(seconds=1) #update current time

    #lexicographic sort by time counts (reverse order), then datetime (increasing order)
    sorted_time_counts = sorted(start_times.items(), key=lambda x: (-x[1],x[0]))
    #looks like [(time1, count1), (time2, count2), ...]

    with open(out3_path,'wb') as f:
        for i in range(10):
            try:
                t = sorted_time_counts[i][0]
                dt = datetime.strftime(t, '%d/%b/%Y:%H:%M:%S') + " -0400"
                f.write(dt+","+str(sorted_time_counts[i][1])+"\n")
            except IndexError:
                pass


def run_feature4(out4_path, inp_list, inp):
    """
    Feature 4: Detects patterns of three failed login attempts from the same IP address over 20 seconds so that all further attempts to the site can be blocked for 5 minutes. Logs those possible security breaches.
    """

    ip_ts = map(lambda x: (x[0], convert_to_datetime(x[1]), int(x[3])), inp_list) #remove timezone, get list
    zipped_ip = zip(range(len(ip_ts)), ip_ts) #zip to add index
    sorted_ip = sorted(zipped_ip, key = lambda x: x[1][1]) #sort by datetime
    sort_order = map(lambda x: x[0], sorted_ip) #get sorted indices

    blocked = {} #looks like {ip1: block_end_time1, ...}
    ip_strikes = {} #looks like {ip1: [strike_end_time1, num_strikes]}
    out_blocked = [] #output

    for i in sort_order: #iterate over time-sorted login queries

        curr_login = ip_ts[i] #of form [ip, timestamp, http]

        if curr_login[2] == 401: #failed login

            #case 1: IP is in block list
            if curr_login[0] in blocked:

                #case 1a: within 5 minute cutoff
                if curr_login[1] <= blocked[curr_login[0]]:

                    out_blocked.append(inp[i]) #add to blocked.txt

                else: #case 1b: IP is in block list but 5 minutes passed
                    blocked.pop(curr_login[0], None) #remove IP from block list
                    ip_strikes.pop(curr_login[0], None) #remove IP from strike list

            #case 2: IP not in block list but is in strike list
            elif curr_login[0] in ip_strikes:

                #case 2a: within 20 seconds of first strike
                if curr_login[1] <= ip_strikes[curr_login[0]][0]:
                    ip_strikes[curr_login[0]][1] += 1 #add strike

                    #three strikes are done, add IP to block list
                    if ip_strikes[curr_login[0]][1] == 3:
                        blocked[curr_login[0]] = curr_login[1] + timedelta(minutes=5) #create block and start 5-minute timer

                else: #case 2b: 20 seconds have passed
                    ip_strikes.pop(curr_login[0], None) #remove IP from strike list

            else: #case 3: failed IP not in block or strike list i.e. first strike
                ip_strikes[curr_login[0]] = [curr_login[1] + timedelta(seconds=20), 1] #create strike and start 20-second timer

        else: #case 4: IP is successful

                #case 4a: IP is blocked
                if curr_login[0] in blocked: #remove IP from strike list

                    if curr_login[1] <= blocked[curr_login[0]]: #5 minutes not passed
                        out_blocked.append(inp[i]) #add to blocked.txt

                    else: #case 2: IP is in block list but 5 minutes passed
                        blocked.pop(curr_login[0], None) #remove IP from block list
                        ip_strikes.pop(curr_login[0], None) #remove IP from strike list

                #case 4b: IP not blocked but in strike list
                elif curr_login[0] in ip_strikes:
                    ip_strikes.pop(curr_login[0], None) #remove IP from strike list

                #case 4c: successful IP not in block or strike list; do nothing
                else:
                    continue

    with open(out4_path,'wb') as f:
        for i in range(len(out_blocked)):
            f.write(out_blocked[i]+"\n")


def run_feature5(out5_path, inp_list):
    """
    Feature 5: Decreasing count of HTTP reply codes.
    """
    http = {} #looks like {http1: count1, ...}
    for inp in inp_list: #for each request
        try:
            if http[inp[3]]:
                http[inp[3]] += 1 #update host-count dictionary
        except KeyError:
            http[inp[3]] = 1

    #lexicographic sort by host counts
    sorted_http = sorted(http.items(), key=lambda x: (-x[1],x[0]))

    with open(out5_path,'wb') as f:
        for i in range(10):
            try:
                f.write(sorted_http[i][0]+","+str(sorted_http[i][1])+"\n")
            except IndexError:
                pass

def run_feature6(out6_path, inp_list):
    """
    Feature 6: Quantify activity of top 10 hosts/IPs (feature 1) across the day (60-minute intervals).
    """

    hosts = {} #looks like {host1: count1, ...}
    for inp in inp_list: #for each request
        try:
            if hosts[inp[0]]:
                hosts[inp[0]] += 1 #update host-count dictionary
        except KeyError:
            hosts[inp[0]] = 1

    #lexicographic sort by host counts
    sorted_hosts = sorted(hosts.items(), key=lambda x: (-x[1],x[0]))

    top10_hosts = dict(sorted_hosts[:10]).keys()

    host_activity = {} #looks like {host1: [count1, count2, ..., count24], ...} i.e. count for each hour

    #initialize
    for host in top10_hosts:
        host_activity[host] = [0]*24

    for inp in inp_list: #for each request
        if inp[0] in top10_hosts:
            t = convert_to_datetime(inp[1])
            # print inp[0],t
            try:
                host_activity[inp[0]][t.hour] += 1 #update host-count dictionary
            except ValueError:
                host_activity[inp[0]][0] += 1

    with open(out6_path,'wb') as f:
        for i in top10_hosts: #for each top host
            for h in range(24): #for each hour
                try:
                    f.write(str(i)+","+str(h)+","+str(host_activity[i][h])+"\n")
                except IndexError:
                    pass



def main():

    args = []
    for arg in sys.argv:
        args.append(arg)

    #read input and output paths for default features.
    input_path = str(args[1])
    out1_path = str(args[2])
    out2_path = str(args[3])
    out3_path = str(args[4])
    out4_path = str(args[5])

    #set True to run extra features and generate outputs below.
    run_extra_features = False
    out5_path = './log_output/feat5.txt'
    out6_path = './log_output/feat6.txt'

    inp = []
    with open(input_path,'r') as f:
        for line in f:
            inp.append(line)

    def parse_line(line):
        """
        Parses input request into corresponding fields below.
        """
        line = line.rstrip("\n").rstrip().lstrip()
        host = line.split("- -")[0].rstrip().lstrip()
        timestamp = line[line.find("[")+1:line.find("]")]
        request = re.findall('"([^"]*)"', line)[0]
        http = line.split(" ")[-2]
        byte = line.split(" ")[-1]
        if byte == "-":
            byte = '0'

        return [host, timestamp, request, http, byte]


    inp_list = map(lambda x: parse_line(x), inp) #parses input

    #run features/analytics
    run_feature1(out1_path, inp_list)
    run_feature2(out2_path, inp_list)
    run_feature3(out3_path, inp_list)
    run_feature4(out4_path, inp_list, inp)

    if run_extra_features: #default False
        run_feature5(out5_path, inp_list)
        run_feature6(out6_path, inp_list)

if __name__ == '__main__':
    main()