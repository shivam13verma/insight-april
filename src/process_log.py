import sys
import re
from datetime import timedelta
from datetime import datetime
from collections import defaultdict, deque

def run_feature1(out1_path, inp_list):
    """
    Feature 1: List in descending order of the top 10 most active hosts/IP addresses that have accessed the site.
    """
    hosts = {}
    for inp in inp_list:
        try:
            if hosts[inp[0]]:
                hosts[inp[0]] += 1
        except KeyError:
            hosts[inp[0]] = 1

    sorted_hosts = sorted(hosts.items(), key=lambda x: x[1], reverse=True)

    with open(out1_path,'wb') as f:
        for i in range(10):
            f.write(sorted_hosts[i][0]+","+str(sorted_hosts[i][1])+"\n")


def run_feature2(out2_path, inp_list):
    """
    Feature 2: Identify the top 10 resources on the site that consume the most bandwidth.
    """

    resources = {}
    for inp in inp_list:
        res = inp[2].split(" ")[1] #resource
        byte = int(inp[-1])
        try:
            if resources[res]:
                resources[res] += byte
        except KeyError:
            resources[res] = byte

    sorted_resources = sorted(resources.items(), key=lambda x: x[1], reverse=True)

    with open(out2_path,'wb') as f:
        for i in range(10):
            f.write(sorted_resources[i][0]+"\n")

def convert_to_datetime(ts):
    formats = ['%d/%b/%Y:%H:%M:%S','%d/%b/%Y:%H:%M', '%d/%b/%Y:%H', '%d/%b/%Y']
    ts = ts.split(" ")[0].rstrip(":") #remove timezone
    out = datetime(1111, 1, 1, 0, 0, 0) #default time if nothing works
    for f in formats:
        try:
            out = datetime.strptime(ts, f)
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
    start_times = {}
    curr_time = sorted_timestamps[0]
    end_time = sorted_timestamps[-1]

    while curr_time < end_time: #for each start time

        if curr_time not in start_times:
            start_times[curr_time] = 0

        cutoff = curr_time + timedelta(minutes=60) #60-min. cutoff for curr_time

        for x in sorted_timestamps: #for each sorted timestamp
            if x <= cutoff: #if below cutoff
                start_times[curr_time] += 1
            else:
                break

        curr_time = curr_time + timedelta(seconds=1) #update current time


    sorted_time_counts = sorted(start_times.items(), key=lambda x: x[1], reverse=True)
    #looks like [(time1, count1), (time2, count2), ...]

    with open(out3_path,'wb') as f:
        for i in range(10):
            f.write(sorted_time_counts[i][0]+"\n")


def run_feature4(out4_path, inp_list, inp):
    """
    Feature 4: Detects patterns of three failed login attempts from the same IP address over 20 seconds so that all further attempts to the site can be blocked for 5 minutes. Logs those possible security breaches.
    """

    ip_ts = map(lambda x: (x[0], convert_to_datetime(x[1]), int(x[3])), inp_list) #remove timezone, get list
    zipped_ip = zip(range(len(ip_ts)), ip_ts)
    sorted_ip = sorted(ip_ts, key = lambda x: x[1][1])
    sort_order = map(lambda x: x[0], sorted_ip)

    blocked = {} #{ip1: block_end_time1, ...}
    ip_strikes = {} #{ip1: [strike_end_time1, strikes]}
    out_blocked = []

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
                    ip_strikes[curr_login[0]][1] += 1

                    #three strikes are done, add IP to block list
                    if ip_strikes[curr_login[0]][1] == 3:
                        blocked[curr_login[0]] = curr_login[1] + timedelta(minutes=5)

                else: #case 2b: 20 seconds have passed
                    ip_strikes.pop(curr_login[0], None) #remove IP from strike list

            else: #case 3: failed IP not in block or strike list i.e. first strike
                ip_strikes[curr_login[0]] = [curr_login[1] + timedelta(seconds=20), 1]

        else: #case 4: IP is successful

                #case 4a: IP is blocked
                if curr_login[0] in blocked: #remove IP from strike list

                    if curr_login[1] <= blocked[curr_login[0]]: #5 minutes not passed
                        out_blocked.append(inp[i]) #add to blocked.txt

                    else: #case 2: IP is in block list but 5 minutes passed
                        blocked.pop(curr_login[0], None)
                        ip_strikes.pop(curr_login[0], None)

                #case 4b: IP not blocked but in strike list
                elif curr_login[0] in ip_strikes:
                    ip_strikes.pop(curr_login[0], None) #remove IP from strike list

                #case 4c: successful IP not in block or strike list; do nothing
                else:
                    continue

    with open(out4_path,'wb') as f:
        for i in range(len(out_blocked)):
            f.write(out_blocked[i]+"\n")



def main():

    args = []
    for arg in sys.argv:
        args.append(arg)

    input_path = str(args[1])
    out1_path = str(args[2])
    out2_path = str(args[3])
    out3_path = str(args[4])
    out4_path = str(args[5])
    #out5_path = str(args[7]) #uncomment this when running feature5.
    #out6_path = str(args[8]) #uncomment this when running feature6.

    #batch_path = './paymo_input/batch_payment.txt'
    #stream_path = './paymo_input/stream_payment.txt'
    #out1_path = './paymo_output/output1.txt'
    #out2_path = './paymo_output/output2.txt'
    #out3_path = './paymo_output/output3.txt'
    #out4_path = './paymo_output/output4.txt'
    #out5_path = './paymo_output/output5.txt'
    #out5_path = './paymo_output/output6.txt'

    inp = []
    with open(input_path,'r') as f:
        for line in f:
            inp.append(line)

    def parse_line(line):

        line = line.rstrip("\n").rstrip().lstrip()
        host = line.split("- -")[0].rstrip().lstrip()
        timestamp = line[line.find("[")+1:test.find("]")]
        request = re.findall('"([^"]*)"', line)[0]
        http = line.split(" ")[-2]
        byte = line.split(" ")[-1]
        if byte == "-":
            byte = '0'

        return [host, timestamp, request, http, byte]


    inp_list = map(lambda x: parse_line(x), inp) #contains list of form [['id1','id2'],['id3','id4'],...]

    run_feature1(out1_path, inp_list)
    run_feature2(out2_path, inp_list)
    run_feature3(out3_path, inp_list)
    run_feature4(out3_path, inp_list, inp)
    #run_feature4(out4_path, stream_list, batch_dict, k=10) #uncomment this when running feature4.
    #run_feature5(out5_path, stream, batch, last_transaction = 365) #uncomment this when running feature5.
    #run_feature5(out6_path, stream, batch, mult_factor = 1.5) #uncomment this when running feature6.

if __name__ == '__main__':
    main()