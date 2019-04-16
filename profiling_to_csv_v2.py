from __future__ import division
import sys
import os
from Naked.toolshed.shell import execute_js, muterun_js
import json
import csv
import numpy as np
import pandas as pd
import time
import subprocess
import shlex
import datetime
import shutil

#put the url here, in the format shown
url_src_path="./top50.txt"
profile_dir=os.path.expandvars("$PWD/")
output_dir="output"
file_dir="file"
debug_msg_level=1
targetsite_base="https://www.instagram.com/"
chrome_cache_dir=os.path.expandvars("$PWD/logs/chrome-profiling/Default/Cache")

###############################################################################

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


###############################################################################

def print_dbg_msg_L1(msg):
    if (debug_msg_level >= 1):
        print( bcolors.OKGREEN +  str(datetime.datetime.now()) + " " + msg + bcolors.ENDC)


###############################################################################
        
def populate_list(src_file):
    return [line.rstrip('\n') for line in open(src_file)]

def get_ip():
    GET_IP_CMD ="hostname -I"
    return subprocess.check_output(GET_IP_CMD, shell=True).decode('utf-8') 

def process_profile():
    URL = []
    #rootdir=r'C:\Users\dcswaka\.spyder-py3\facebook\testing\file' #directory where you put the output browser profiles
    rootdir=os.path.join(profile_dir+file_dir)
    counter=1
    identity=1 #counter for the number of profiles to be loaded
    URL = populate_list(url_src_path)
    ip_addr = get_ip()

    identity_base = 1
    counter_base = 1

    print_dbg_msg_L1("[+] identity_base / counter_base: " + str(identity_base) + "/" + str(counter_base))

    for identity in range(identity_base,51): #profiles 1-50
        print_dbg_msg_L1("[+] Run " + str(int(identity)-1))
        # edit the get-timeline-trace.js to add in targeted url link and save into the targeted JSON file (I here name profiles as 1,2,3... 
        # so JSON files are saved as 1.JSON so on)
        with open('get-timeline-trace.js', 'rt') as fin, open('profiling.js', 'wt') as fout:
            for line in fin:
                if "Page.navigate({'url':" in line:
                    line = "        Page.navigate({'url': '" + targetsite_base + URL[(int(identity)-1)]+"'})\n"
                if "var file = 'profile-" in line:
                    line="            var file='./file/"+str(identity)+"/"+"0.JSON';\n"
                fout.write(line)
        #print_dbg_msg_L1("[+] Creating output dirs ...")
        if not os.path.exists('./output/'+str(identity)+'/'):
            os.makedirs('./output/'+str(identity)+'/')
        if not os.path.exists('./file/'+str(identity)+'/'):
            os.makedirs('./file/'+str(identity)+'/')
        #os.makedirs(os.path.join(output_dir, str(identity)))
        #os.makedirs(os.path.join(file_dir, str(identity)))

        t=0 
        #counter=1
        for counter in range(counter_base,101):
            skip_run = 0
            if os.path.exists(chrome_cache_dir):
                print_dbg_msg_L1("[+] Cleaing up cache ...")
                shutil.rmtree(chrome_cache_dir,ignore_errors=True)
            # start chrome
            #chrome_cmd="google-chrome --remote-debugging-port=9222 --no-default-browser-check --user-data-dir=$PWD/logs/chrome-profiling/ --headless &"
            #p_chrome=""
            #p_chrome = subprocess.Popen(shlex.split(chrome_cmd))
            target_output_filename=rootdir+os.sep+str(identity)+os.sep+str(counter)+'.JSON'
            
            while True:    
                if os.path.exists(target_output_filename):
                    #print_dbg_msg_L1("\t[+] Skipping collection...")
                    skip_run = 1
                    break

                print_dbg_msg_L1("[+] counter " + str(counter))

                # start tcpdump
                pcap_logfile= "%s/%d/%d_%d.pcap" % (rootdir, identity, int(identity)-1, int(counter)-1)
                tcpdump_cmd = "tcpdump 'tcp and host " + ip_addr + "' -ttttt -nn -U -w " + pcap_logfile
                print_dbg_msg_L1("\t[+] starting tcpdump...")
                p = ""
                p = subprocess.Popen(shlex.split(tcpdump_cmd))
                time.sleep(1)

                start_time=time.time()
                #print(start_time)
                print_dbg_msg_L1("\t[+] Browser start...")
                response = muterun_js('profiling.js') #execute the javascript for chrome profiling download
                print_dbg_msg_L1("\t[+] Browser complete!")
                if response.exitcode == 0:
                    print(response.stdout)
                    #time.sleep(3)
                else:
                    sys.stderr.write(response.stderr)
                
                # stop tcpdump, write to file
                print_dbg_msg_L1("\t[+] Killing tcpdump...")
                p.kill()
                p.wait()

                if response.exitcode == 0:
                    # convert pcap file into plain text
                    pcap_plaintext= "%s/%d/%d_%d.pcap.txt" % (rootdir, identity, int(identity)-1, int(counter)-1)
                    tcpdump_r_cmd = shlex.split("tcpdump -ttttt -nn -r " + pcap_logfile)
                    print_dbg_msg_L1("\t[+] Creating plaintext logfile...")
                    logfile = open(pcap_plaintext, "w")
                    print_dbg_msg_L1("\t[+] Starting pcap conversion...")
                    p_r = subprocess.Popen(tcpdump_r_cmd, stdout=logfile)
                    p_r.wait()
                    logfile.close()

                if not os.path.exists(rootdir+os.sep+str(identity)+'/0.JSON'):
                    print_dbg_msg_L1("\t[+] JSON file not found, re-running current counter...")
                else:
                    break

            if skip_run == 1:
                continue

            #chnage the JSON file name to be in the format of identity.JSON
            #print_dbg_msg_L1("[+] Directory: " + rootdir+os.sep+str(identity))
            #for filename in os.listdir(rootdir+os.sep+str(identity)):
                #print_dbg_msg_L1("[+] Checking " + filename + " ...")
            filename = "0.JSON"
            if os.path.exists(rootdir+os.sep+str(identity)+os.sep+filename):
                filepath=rootdir+os.sep+str(identity)+os.sep+filename
                newname=str(counter)+'.JSON'
                print_dbg_msg_L1("\t[+] Renaming " + filepath + " to " + rootdir+os.sep+str(identity)+os.sep+newname + " ...")
                os.rename(filepath, rootdir+os.sep+str(identity)+os.sep+newname)


            #parse the json file and write some targeted parameters into the csv file
            with open(rootdir+os.sep+str(identity)+'/'+str(counter)+'.JSON') as f: #open and readin the json file to be parsed
                    d = json.load(f)
                    i = 0
                    total=0
                    init_time=d[0]['ts']
                    with open('./output/'+str(identity)+'/'+str(counter)+'.csv', 'w') as f: #open the csv file to be output
                        w = csv.writer(f, delimiter=',')
                        w.writerow(['Length', 'totallength', 'starttime', 'endtime', 'timestamp','type'])
                        while i < len(d):
                            row=[]
                            #print_dbg_msg_L1("\t[+] " + d[i]["name"])
                            if d[i]["name"] == "ResourceReceiveResponse":
                                rid=d[i]["args"]["data"]["requestId"]
                                datatype=d[i]["args"]["data"]["mimeType"]
                                #print_dbg_msg_L1("\t[+] Processing for datatype " + str(datatype) + " and rid = " + str(rid))
                                t+=1
                                linenum=0
                                while linenum <len(d)-1:
                                    linenum+=1
                                    if d[linenum]["name"]=="ResourceSendRequest" and d[linenum]["args"]["data"]["requestId"]==rid:
                                        start_time="%.6f" % ((d[linenum]['ts']-init_time)/1000000)
                                        #print_dbg_msg_L1("\t[+] Start time is " + str(start_time))
                                        
                                    if d[linenum]["name"]=="ResourceFinish" and d[linenum]["args"]["data"]["requestId"]==rid:
                                        file_length=d[linenum]['args']['data']['decodedBodyLength']
                                        end_time="%.6f" % ((d[linenum]['ts']-init_time)/1000000)
                                        #print_dbg_msg_L1("\t[+] Found! Length of response is " + str(file_length))
                                        #print_dbg_msg_L1("\t[+] End time is " + str(end_time))
                                        break
                                
                                time_taken="%.6f" % ((d[i]['ts']-init_time)/1000000)
                                #print_dbg_msg_L1("\t[+] Time taken: " + str(time_taken))
                                total+=file_length
                                if file_length>500:
                                    row=np.append(row, file_length)
                                    row=np.append(row, total)
                                    row=np.append(row, start_time)
                                    row=np.append(row, end_time)
                                    row=np.append(row, time_taken)
                                    row=np.append(row, datatype)
                                    w.writerow(row)
                                    #print(d[i]['ts'])    
                            i += 1
                        print_dbg_msg_L1("[+] File processing complete!\n")
            #some formatting of the csv file created 
            df = pd.read_csv('./output/'+str(identity)+'/'+str(counter)+'.csv')
            df.sort_values('starttime').to_csv('./output/'+str(identity)+'/'+str(counter)+'.csv')
            df_sorted=df.sort_values('starttime')
            init_t=df_sorted['starttime'].iloc[0]
            #df_sorted['timestamp']=df_sorted['timestamp']-init_t
            if not os.path.exists('./output/'+str(identity)+'/'):
                os.makedirs('./output/'+str(identity)+'/')
            df_sorted.to_csv('./output/'+str(identity)+'/'+str(counter)+'_2.csv')                    
            t=0
            end_time=time.time()
            #sleeptime=5-(end_time-start_time)
            #time.sleep(sleeptime)


process_profile()