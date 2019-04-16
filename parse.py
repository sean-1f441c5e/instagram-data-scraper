import os
import sys
import argparse
import pandas
import datetime
import json
import csv
import numpy as np
import statistics
import random

src_dir = "./data"
src_dir_2 = "./file"
dst_dir = "./pre-processed_tor_weka"
debug_msg_level=1

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
        print bcolors.OKGREEN + msg + bcolors.ENDC


###############################################################################

def dummy_func():
    return

def parse_for_k_fingerprinting():
    # get listing of all files to process
    print_dbg_msg_L1("[+] Getting list of pcap files to process...")
    pcap_files = [f for f in os.listdir(src_dir) if f.endswith('.txt')]

    # create the output folder if required
    if not os.path.exists(dst_dir):
        print_dbg_msg_L1("[+] Output directory " + dst_dir + " not found, creating...")
        os.mkdir(dst_dir)

    for pcap_file in pcap_files:
    #pcap_file = pcap_files[0]
        parsed_data_file=(dst_dir + "/" + pcap_file).replace(".pcap.txt","")
        if os.path.exists(parsed_data_file):
            continue
        f = open(src_dir + "/" + pcap_file, "r")
        raw_data = [line.rstrip('\n') for line in f]
        f.close()

        parsed_data = []
        src = ""
        skip_lines=0

        if pcap_files.index(pcap_file) < 100:
            if pcap_files.index(pcap_file) > 0 and pcap_files.index(pcap_file) % 10 == 0:
                print_dbg_msg_L1("\t[+] Processing " + str(pcap_files.index(pcap_file)))
        elif pcap_files.index(pcap_file) % 100 == 0:
            print_dbg_msg_L1("\t[+] Processing " + str(pcap_files.index(pcap_file)))

        #print_dbg_msg_L1("\t[+] Processing " + dst_dir + "/" + pcap_file)

        for line in raw_data:
            index = raw_data.index(line)
            #print_dbg_msg_L1("\t[+] Processing line " + str(index) + "...")
            #if (index > 0 and \
                #index < (len(raw_data) - 1)):

            # for some reason, sometimes empty lines appear in the plaintext data
            # just skip to the next line
            if not " " in line:
                continue

            parsed = line.split(" ")

            if (skip_lines == 1 and index == (len(raw_data) -1)):
                #print_dbg_msg_L1("\t[+] Skipping last line...")
                break

            if (parsed[0] == "reading"):
                #print_dbg_msg_L1("\t[+] Non-data line, skipping...")
                skip_lines = 1
                continue

            # parse for time
            # Tcpdump sometimes throw out wierd output
            # If we cannot parse the line, skip to the next line
            #print_dbg_msg_L1("\t[+] Parsing for time...") 
            time_data_block = parsed[1].split(":")
            if len(time_data_block) > 2:
                packet_elapse_time = time_data_block[2]
            else:
                continue

            # Parse for len. The position of the length value is not always 
            # consistent, so we will check in reverse for the string "length".
            # The value following that is always length value of the packet
            #print_dbg_msg_L1("\t[+] Parsing for length...")
            for j in range(len(parsed)-1,0,-1):
                if not parsed[j].isdigit():
                    if str(parsed[j]).startswith("length"):
                        packet_len = parsed[j+1]

            # parse for direction
            #print_dbg_msg_L1("\t[+] Parsing for direction...") 
            try:
                if (len(src) == 0):
                    ip_addr = parsed[3].split(".")
                    # sanity check - the src ip must be our own, of the range 192.168.0.0/16
                    if ip_addr[0].isdigit() and int(ip_addr[0]) == 192 and int(ip_addr[1]) == 168:
                        src = ip_addr[0] + "." + ip_addr[1] + "." + ip_addr[2] + "." + ip_addr[3]
                    else:
                        # grab the 2nd part, somehow we missed out on 1 packet exchange
                        ip_addr = parsed[5].split(".")
                        src = ip_addr[0] + "." + ip_addr[1] + "." + ip_addr[2] + "." + ip_addr[3]
            except Exception as e:
                print_dbg_msg_L1("[+] Error occured at " + parsed_data_file)
                raise

            if (parsed[3].find(src) == 0):
                packet_direction = 1
            else:
                packet_direction = -1

            parsed_data.append(str(packet_elapse_time) + " " + str(packet_direction) + " " + str(packet_len))

            #else:
                #print_dbg_msg_L1("\t\t[+] Non-data line...")
            
        #print_dbg_msg_L1("\t[+] Writing to file " + parsed_data_file)
        w = open(parsed_data_file, "w")
        for lines in parsed_data:
            w.writelines("%s\n" % lines)
        w.close()

        #if (pcap_files.index(pcap_file) % 10 == 0):
            #print_dbg_msg_L1("\t[+] Done")

    print_dbg_msg_L1("[+] All parsing complete!")

def parse_for_weka():
    # get listing of all files to process
    print_dbg_msg_L1("[+] Getting list of pcap files to process...")
    pcap_files = [f for f in os.listdir(src_dir) if f.endswith('.txt')]

    # create the output folder if required
    if not os.path.exists(dst_dir):
        print_dbg_msg_L1("[+] Output directory " + dst_dir + " not found, creating...")
        os.mkdir(dst_dir)

    for pcap_file in pcap_files:
    #pcap_file = pcap_files[0]
        f = open(src_dir + "/" + pcap_file, "r")
        raw_data = [line.rstrip('\n') for line in f]
        f.close()

        parsed_data = []
        src = ""
        filename_index=pcap_file.replace(".pcap.txt","").split("_")
        parsed_data_file=dst_dir + "/" + filename_index[0] + "-" + filename_index[1]
        skip_lines=0

        if pcap_files.index(pcap_file) < 100:
            if pcap_files.index(pcap_file) > 0 and pcap_files.index(pcap_file) % 10 == 0:
                print_dbg_msg_L1("\t[+] Processing " + str(pcap_files.index(pcap_file)))
        elif pcap_files.index(pcap_file) % 100 == 0:
            print_dbg_msg_L1("\t[+] Processing " + str(pcap_files.index(pcap_file)))

        #print_dbg_msg_L1("\t[+] Processing " + dst_dir + "/" + pcap_file)

        for line in raw_data:
            index = raw_data.index(line)
            #print_dbg_msg_L1("\t[+] Processing line " + str(index) + "...")
            #if (index > 0 and \
                #index < (len(raw_data) - 1)):

            # for some reason, sometimes empty lines appear in the plaintext data
            # just skip to the next line
            if not " " in line:
                continue

            parsed = line.split(" ")

            if (skip_lines == 1 and index == (len(raw_data) -1)):
                #print_dbg_msg_L1("\t[+] Skipping last line...")
                break

            if (parsed[0] == "reading"):
                #print_dbg_msg_L1("\t[+] Non-data line, skipping...")
                skip_lines = 1
                continue
            
            # parse for time
            # Tcpdump sometimes throw out wierd output
            # If we cannot parse the line, skip to the next line
            #print_dbg_msg_L1("\t[+] Parsing for time...") 
            time_data_block = parsed[1].split(":")
            if len(time_data_block) > 2:
                packet_elapse_time = time_data_block[2]
            else:
                continue

            # Parse for len. The position of the length value is not always 
            # consistent, so we will check in reverse for the string "length".
            # The value following that is always length value of the packet
            #print_dbg_msg_L1("\t[+] Parsing for length...")
            for j in range(len(parsed)-1,0,-1):
                if not parsed[j].isdigit():
                    if str(parsed[j]).startswith("length"):
                        packet_len = parsed[j+1]

            #try:
            # parse for direction
            #print_dbg_msg_L1("\t[+] Parsing for direction...") 
            if (len(src) == 0):
                ip_addr = parsed[3].split(".")
                # sanity check - the src ip must be our own, of the range 192.168.0.0/16
                if ip_addr[0].isdigit() and int(ip_addr[0]) == 192 and int(ip_addr[1]) == 168:
                    src = ip_addr[0] + "." + ip_addr[1] + "." + ip_addr[2] + "." + ip_addr[3]
                else:
                    # grab the 2nd part, somehow we missed out on 1 packet exchange
                    ip_addr = parsed[5].split(".")
                    src = ip_addr[0] + "." + ip_addr[1] + "." + ip_addr[2] + "." + ip_addr[3]
                #print_dbg_msg_L1("\t[+] src ip: " + src)

            if parsed[3].find(src) == 0:
                packet_direction = 1
            else:
                packet_direction = -1

            parsed_data.append(str(packet_elapse_time) + "\t" + str(packet_direction))
            #except:
                #print_dbg_msg_L1("[+] Error in parsing file " + pcap_file)
                #break

            #else:
                #print_dbg_msg_L1("\t\t[+] Non-data line...")
            
        #print_dbg_msg_L1("\t[+] Writing to file " + parsed_data_file)
        w = open(parsed_data_file, "w")
        for lines in parsed_data:
            w.writelines("%s\n" % lines)
        w.close()

        '''
        if (pcap_files.index(pcap_file) < 100):
            if (pcap_files.index(pcap_file) % 10 == 0):
                print_dbg_msg_L1("\t[+] Done!")
        elif pcap_files.index(pcap_file) % 100 == 0:
            print_dbg_msg_L1("\t[+] Done!")
        '''

    print_dbg_msg_L1("[+] All parsing complete!")

def parse_for_new(filter_len=0):
    '''
    1) read raw output from new method

    2) read file list from pre-processed

    3) We'll match of the first record of each
        - read raw new_output and create a list of new_timing and new_size
        - for each timing-size pair
            > read pre-processed in lines
            > for each line, check the timing
            > if timing >= new_timing
            >   while size < new_size
            >   feed into new_list
            > move to next timing
            >   duplicates are fine, we'll remove it later
            > once done, de-dup the list
            > output to new_file
    '''
    
    # read raw output from new method
    # open up csv file in pandas
    for user_index in range(1,51):
        print_dbg_msg_L1("[+] Run " + str(user_index))
        for run_index in range(1,101):
            normalized_output_path = dst_dir + "/" + str(user_index) + "_" + str(run_index-1)
            if os.path.exists(normalized_output_path):
                #print_dbg_msg_L1("Normalized output file for " + str(user_index) + "_" + str(run_index-1) + " found, skipping...")
                continue

            src_file_path=src_dir + "/" + str(user_index) + "/" + str(run_index) + ".csv"
            #print_dbg_msg_L1("\t[+] Processing " + src_file_path)
            csv_data = pandas.read_csv(src_file_path)

            # extract all data pertaining to image/jpeg or image/png
            image_list = []
            for row in csv_data.itertuples():
                if "image" in row.type:
                    image_list.append(row)

            # open up pre-processed file
            pcap_src_file_path=src_dir_2 + "/" + str(user_index) + "/" + str(user_index-1) + "_" + str(run_index-1) + ".pcap.txt"
            #print_dbg_msg_L1("[+] Opening " + src_dir_2 + "/" + str(user_index) + "/" + str(user_index-1) + "_" + str(run_index-1) + ".pcap.txt")

            f = open(pcap_src_file_path, "r")
            pcap_raw_data = [line.rstrip('\n') for line in f]
            f.close()

            parsed_data = []
            skip_lines = 0
            src = ""
            parsed_data_file=src_dir + "/" + str(user_index) + "/" + str(user_index) + "_" + str(run_index-1) + "_raw"

            for line in pcap_raw_data:
                index = pcap_raw_data.index(line)
                #print_dbg_msg_L1("\t[+] Processing line " + str(index) + "...")
                #if (index > 0 and \
                    #index < (len(pcap_raw_data) - 1)):

                # for some reason, sometimes empty lines appear in the plaintext data
                # just skip to the next line
                if not " " in line:
                    continue

                parsed = line.split(" ")

                if (skip_lines == 1 and index == (len(pcap_raw_data) -1)):
                    #print_dbg_msg_L1("\t[+] Skipping last line...")
                    break

                if (parsed[0] == "reading"):
                    #print_dbg_msg_L1("\t[+] Non-data line, skipping...")
                    skip_lines = 1
                    continue
                
                # parse for time
                # Tcpdump sometimes throw out wierd output
                # If we cannot parse the line, skip to the next line
                #print_dbg_msg_L1("\t[+] Parsing for time...") 
                time_data_block = parsed[1].split(":")
                if len(time_data_block) > 2:
                    packet_elapse_time = time_data_block[2]
                else:
                    continue

                # Parse for len. The position of the length value is not always 
                # consistent, so we will check in reverse for the string "length".
                # The value following that is always length value of the packet
                #print_dbg_msg_L1("\t[+] Parsing for length...")
                for j in range(len(parsed)-1,0,-1):
                    if not parsed[j].isdigit():
                        if str(parsed[j]).startswith("length"):
                            packet_len = parsed[j+1].split(":")[0]
                            #print_dbg_msg_L1("\t\t[+] Packet len: " + str(packet_len))

                #try:
                # parse for direction
                #print_dbg_msg_L1("\t[+] Parsing for direction...") 
                if (len(src) == 0):
                    ip_addr = parsed[3].split(".")
                    # sanity check - the src ip must be our own, of the range 192.168.0.0/16
                    if ip_addr[0].isdigit() and int(ip_addr[0]) == 192 and int(ip_addr[1]) == 168:
                        src = ip_addr[0] + "." + ip_addr[1] + "." + ip_addr[2] + "." + ip_addr[3]
                    else:
                        # grab the 2nd part, somehow we missed out on 1 packet exchange
                        ip_addr = parsed[5].split(".")
                        src = ip_addr[0] + "." + ip_addr[1] + "." + ip_addr[2] + "." + ip_addr[3]
                    #print_dbg_msg_L1("\t[+] src ip: " + src)

                if parsed[3].find(src) == 0:
                    packet_direction = 1
                else:
                    packet_direction = -1

                parsed_data.append(str(packet_elapse_time) + " " + str(packet_direction) + " " + str(packet_len))
                #except:
                    #print_dbg_msg_L1("[+] Error in parsing file " + pcap_file)
                    #break

                #else:
                    #print_dbg_msg_L1("\t\t[+] Non-data line...")
                    
                #print_dbg_msg_L1("\t[+] Writing to file " + parsed_data_file)
            #print_dbg_msg_L1("\t[+] Writing to " + str(parsed_data_file))
            w = open(parsed_data_file, "w")
            for lines in parsed_data:
                w.writelines("%s\n" % lines)
            w.close()

            preprocessed_data=pandas.read_csv(parsed_data_file)

            final_list = []
            image_block_found=0
            counter_base = 0
            start_time_found = 0
            end_time_found = 0
            current_start_time = 0
            current_end_time = 0
            
            # assume consecutive 3 or more image downloads together
            #print_dbg_msg_L1("\t[+] List length is " + str(len(image_list)))
            for i in range(1, len(image_list)):
                #print_dbg_msg_L1("\t[+] Type check: " + image_list[i].type)
                if "image" in image_list[i].type:
                    image_block_found += 1
                else:
                    image_block_found = 0
                
                if image_block_found > 2:
                    counter_base = i
                    try:
                        current_start_time = datetime.datetime.strptime(str(format(image_list[i-2].starttime, ".6f")), "%S.%f")
                        current_end_time = datetime.datetime.strptime(str(format(image_list[i-2].endtime, ".6f")), "%S.%f")
                    except Exception as e:
                        #print "Error occured at %s at position %d of %d\n" % (src_file_path, i, len(image_list))
                        #print "Offending line is %s\n" % (str(image_list[i-2].starttime))
                        print e
                        raise
                    #print_dbg_msg_L1("\t[+] Found image block! Timing starting at " + str(current_start_time))
                    #for k in range(0,3):
                        #print_dbg_msg_L1("\t[+] T" + str(k) + ": " + str(image_list[i-2+k].starttime))
                    break
                
            #print_dbg_msg_L1("[+] Finding " + str(image_list[i-2].starttime) + "...")
            for item in preprocessed_data.itertuples():
                preprocessed_data_time = datetime.datetime.strptime(str(item[1].split(" ")[0]), "%S.%f")
                #print_dbg_msg_L1("\t\t[+] current_start_time: " + str(current_start_time))
                #print_dbg_msg_L1("\t\t[+] preprocessed_data_time: " + str(preprocessed_data_time))
                if start_time_found == 0 and preprocessed_data_time > current_start_time:
                    start_time_found = 1
                    #print_dbg_msg_L1("\t[+] Found suitable start timing: " + str(item[1].split(" ")[0]))
                    #print_dbg_msg_L1("\t\t[+] Direction: " + str(item[1].split(" ")[1]))
                    #print_dbg_msg_L1("\t\t[+] Size: " + str(item[1].split(" ")[2]))
                
                if start_time_found == 1:
                    #print_dbg_msg_L1("\t[+] Checking size: " + item[1].split(" ")[2])
                    final_list.append(item)

            init_time = final_list[0]._1.split(" ")[0]
            last_time = final_list[len(final_list)-1]._1.split(" ")[0]

            normalized_list = []
            temp_node = ""

            #print_dbg_msg_L1("[+] Normalizing timings ...")
            # applying filter here
            for item in final_list:
                item_tokens = item._1.split(" ")
                if int(item_tokens[2].split(":")[0]) < int(filter_len):
                    #print_dbg_msg_L1("\t[+] Filtering: " + item_tokens[2].split(":")[0] + " < " + str(filter_len))
                    item_tokens[2] = 0
                #print_dbg_msg_L1("\t[+] Init / Last / Current : " + str(init_time) + " / "  + str(last_time) + " / " + str(item_tokens[0]))
                #print_dbg_msg_L1("\t[+] Differential: " + str(format((float(item_tokens[0]) - float(init_time)), ".6f")) )
                #print_dbg_msg_L1("\t[+] Divisor: " + str(float(last_time)- float(init_time)) + " / " + str(float(last_time)) + "/" + str(float(init_time)))
                temp_node = str(format((float(item_tokens[0]) - float(init_time))/(float(last_time)- float(init_time)), ".6f")) + " " + item_tokens[1] + " " + str(item_tokens[2])
                #print_dbg_msg_L1("\t[+] Normalized packet timing: " + str(temp_node))
                #print_dbg_msg_L1("")
                normalized_list.append(temp_node)

            # Removing timings that are too far apart
            prev_time_normalized = 0.0
            while True:
                purged = False
                for item in normalized_list:
                    #print_dbg_msg_L1("\t[+] " + item)
                    #print_dbg_msg_L1("\t[+] Timings: " + str(format(float(item.split(" ")[0]), ".6f")) + " / " + str(format(float(prev_time_normalized), ".6f")))
                    #print_dbg_msg_L1("\t[+] Difference: " + str(format(float(item.split(" ")[0]) - float(prev_time_normalized), ".6f")))
                    if int(item.split(" ")[2]) >= int(filter_len):
                        prev_time_normalized = float(item.split(" ")[0])
                    if float(item.split(" ")[0]) - float(prev_time_normalized) > 0.4:
                        #print_dbg_msg_L1("\t\t[+] Purging " + str(format(float(item.split(" ")[0]), ".6f")))
                        normalized_list.remove(item)
                        purged = True
                    else:
                        prev_time_normalized = float(item.split(" ")[0])
                    #print_dbg_msg_L1("")
                if not purged:
                    break
            
            del final_list[:]
            init_time = normalized_list[0].split(" ")[0]
            last_time = normalized_list[len(normalized_list)-1].split(" ")[0]

            # Normalizing remaining timings
            for item in normalized_list:
                item_tokens = item.split(" ")
                if int(item_tokens[2]) < int(filter_len):
                    item_tokens[2] = 0
                #print_dbg_msg_L1("\t[+] Init / Last / Current : " + str(init_time) + " / "  + str(last_time) + " / " + str(item_tokens[0]))
                #print_dbg_msg_L1("\t[+] Differential: " + str(format((float(item_tokens[0]) - float(init_time)), ".6f")))
                #print_dbg_msg_L1("\t[+] Divisor: " + str(float(last_time)- float(init_time)) + " / " + str(float(last_time)) + "/" + str(float(init_time)))
                temp_node = str(format((float(item_tokens[0]) - float(init_time))/(float(last_time)- float(init_time)), ".6f")) + " " + item_tokens[1] + " " + str(item_tokens[2])
                #print_dbg_msg_L1("\t[+] Normalized packet timing: " + str(temp_node))
                #print_dbg_msg_L1("")
                final_list.append(temp_node)


            #print_dbg_msg_L1("\t[+] Writing normalized timings to " + normalized_output_path + "\n")
            if not os.path.exists(dst_dir):
                os.makedirs(dst_dir)
            fn = open(normalized_output_path, "wt") 
            for line in final_list:
                fn.writelines("%s\n" % line)
                #print_dbg_msg_L1("\t[+] " + item)
            fn.close()

    print_dbg_msg_L1("[+] Complete!\n")

    return

def fix_new(user_index, run_index, avg_starttime=0, sd=0):
    #parse the json file and write some targeted parameters into the csv file
    json_file=src_dir_2+'/'+str(user_index)+'/'+str(run_index)+'.JSON'
    #print_dbg_msg_L1("\t\t[+] Opening file " + json_file)
    with open(json_file) as f: #open and readin the json file to be parsed
        t=0
        d = json.load(f)
        i = 0
        total=0
        init_time = 0.0
        if avg_starttime == 0:
            jdf = pandas.read_json(json_file)
            jdf_sorted=jdf.sort_values('ts')
            for line in jdf_sorted.itertuples():
                if line.ts > 0:
                    init_time = line.ts
                    break
        else:       
            init_time=d[0]['ts']
        #print_dbg_msg_L1("[+] Base timing: " + str(init_time) + " / " + str(d[0]['ts']))
        csv_file=src_dir+"/"+str(user_index)+'/'+str(run_index)+'.csv'
        with open(csv_file, 'w') as f: #open the csv file to be output
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
                            #if float(d[linenum]['ts']) < float(init_time):
                                #print_dbg_msg_L1("\t[+] Invalid timing: " + str(format(float(d[linenum]['ts']), ".6f")))
                            start_time="%.6f" % d[linenum]['ts']
                            #print_dbg_msg_L1("\t[+] Start time is " + str(start_time))
                            
                        if d[linenum]["name"]=="ResourceFinish" and d[linenum]["args"]["data"]["requestId"]==rid:
                            file_length=d[linenum]['args']['data']['decodedBodyLength']
                            end_time="%.6f" % d[linenum]['ts']
                            #print_dbg_msg_L1("\t[+] Found! Length of response is " + str(file_length))
                            #print_dbg_msg_L1("\t[+] End time is " + str(end_time))
                            break
                    
                    time_taken="%.6f" % d[i]['ts']
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
    #some formatting of the csv file created 
    df = pandas.read_csv(src_dir+"/"+str(user_index)+'/'+str(run_index)+'.csv')
    df.sort_values('starttime').to_csv('./output/'+str(user_index)+'/'+str(run_index)+'.csv')
    df_sorted=df.sort_values('starttime')

    init_t=df_sorted['starttime'].iloc[0]/1000000
    #print_dbg_msg_L1("\t\t[+] Base timing is " + str(init_t))

    if avg_starttime > 0:
        timing_offset=random.normalvariate(avg_starttime, sd)
        print_dbg_msg_L1("\t\t[+] Avg timing is  " + str(avg_starttime) + " with SD " + str(sd))
        print_dbg_msg_L1("\t\t[+] Generated timing is " + str(timing_offset) + " / " + str(timing_offset*1000000))
        df_sorted['starttime']=(df_sorted['starttime']/1000000 - init_t) + timing_offset
        df_sorted['endtime']=(df_sorted['endtime']/1000000 - init_t) + timing_offset
        df_sorted['timestamp']=(df_sorted['timestamp']/1000000 - init_t) + timing_offset
    else:
        df_sorted['starttime']=(df_sorted['starttime']/1000000 - init_t)
        df_sorted['endtime']=(df_sorted['endtime']/1000000 - init_t)
        df_sorted['timestamp']=(df_sorted['timestamp']/1000000 - init_t)
    
    if not os.path.exists(src_dir+"/"+str(user_index)+'/'):
        os.makedirs(src_dir+"/"+str(user_index)+'/')
    df_sorted.to_csv(src_dir+"/"+str(user_index)+'/'+str(run_index)+'.csv')     

    return

def check_new():
    user_index_max = 51
    run_index_max = 101

    for user_index in range(1,user_index_max):
        print_dbg_msg_L1("[+] Checking " + str(user_index))
        sample = []
        avg_starttime = 0.0
        avg_endtime = 0.0
        avg_timestamp = 0.0
        valid_count=0
        prev_starttime=0.0
        sd = 0.0

        for run_index in range(1,run_index_max):
            src_file_path=src_dir + "/" + str(user_index) + "/" + str(run_index) + ".csv"
            #print_dbg_msg_L1("\t[+] Opening " + src_file_path)
            if not os.path.exists(src_file_path):
                print_dbg_msg_L1("[+] " + str(src_file_path) + " not found, re-parsing from JSON...")
                fix_new(user_index, run_index)
            csv_data = pandas.read_csv(src_file_path)

            for row in csv_data.itertuples():
                #print_dbg_msg_L1("\t\t[+] " + str(format(prev_starttime, ".6f")) + " / "+ str(format(row.starttime, ".6f")))
                if  float(row.starttime) == 0.0:
                    continue
                elif float(row.starttime) > 0.0:
                    if float(avg_starttime) > 0.0:
                        #print_dbg_msg_L1("\t\t[+] Difference: " + str(format(float(row.starttime) - float(prev_starttime), ".6f")))
                        if float(row.starttime) - float(prev_starttime) <= 0.2:
                            valid_count += 1
                            #print_dbg_msg_L1("\t\t[+] Found valid timings...")
                            avg_starttime = float(avg_starttime) + float(row.starttime)
                            avg_endtime = float(avg_endtime) + float(row.endtime)
                            avg_timestamp = float(avg_timestamp) + float(row.timestamp)
                            prev_starttime = float(row.starttime)
                            if valid_count >= 2:
                                sample.append(row.starttime)
                                sd = statistics.stdev(sample)
                                #print_dbg_msg_L1("\t[+] Standard deviation is " + str(sd))
                    else:
                        avg_starttime = float(row.starttime)
                        avg_endtime = float(row.endtime)
                        avg_timestamp = float(row.timestamp)
                        prev_starttime = float(row.starttime)
                        sample.append(row.starttime)
                        valid_count += 1
                break

            if valid_count >= 10:
                break
        
        avg_starttime = float(avg_starttime) / float(valid_count)
        avg_endtime = float(avg_endtime) / float(valid_count)
        avg_timestamp = float(avg_timestamp) / float(valid_count)

        print_dbg_msg_L1("\t[+] Total valid count is " + str(valid_count))
        print_dbg_msg_L1("\t[+] Avg start time is " + str(format(avg_starttime, ".6f")))
        print_dbg_msg_L1("\t[+] Avg end time is " + str(format(avg_endtime, ".6f")))
        print_dbg_msg_L1("\t[+] Avg timestamp is " + str(format(avg_timestamp, ".6f")))

        for run_index in range(1,run_index_max):
            src_file_path=src_dir + "/" + str(user_index) + "/" + str(run_index) + ".csv"
            if not os.path.exists(src_file_path):
                print_dbg_msg_L1("[+] " + str(src_file_path) + " not found, re-parsing from JSON...")
                fix_new(user_index, run_index)

        for run_index in range(1,run_index_max):
            src_file_path=src_dir + "/" + str(user_index) + "/" + str(run_index) + ".csv"
            csv_data = pandas.read_csv(src_file_path)
            prev_starttime = 0.0

            for row in csv_data.itertuples():
                if float(row.starttime) > 0.0:
                    if float(avg_starttime) > 0.0:
                        if prev_starttime == 0.0:
                            prev_starttime = float(row.starttime)
                        elif float(row.starttime) - float(prev_starttime) > 0.2:
                            print_dbg_msg_L1("\t[+] Prev time: " + str(format(float(prev_starttime), ".6f")))
                            print_dbg_msg_L1("\t[+] Start time: " + str(format(float(row.starttime), ".6f")))
                            print_dbg_msg_L1("\t[+] Difference is more than 0.2: " + str(format(float(row.starttime) - float(prev_starttime), ".6f")))
                            print_dbg_msg_L1("\t[+] Fixing " + str(user_index) + "/" + str(run_index))
                            fix_new(user_index, run_index, avg_starttime, sd)
                        else:
                            prev_starttime = float(row.starttime)
                    else:
                        prev_starttime = float(row.starttime)
                elif float(row.starttime) < 0.0:
                    print_dbg_msg_L1("\t[+] Invalid timing values: " + str(format(float(row.starttime), ".6f")))
                    print_dbg_msg_L1("\t[+] Fixing " + str(user_index) + "/" + str(run_index))
                    fix_new(user_index, run_index, avg_starttime, sd)
                break
    
    print_dbg_msg_L1("[+] Check complete!")

    return

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Plaintext pcap trace file parser.')
    parser.add_argument('--k', action='store_true', help='Parses the raw plaintext trace file into input suitable for k-fingerprinting.')
    parser.add_argument('--weka', action='store_true', help='Parses the raw plaintext trace file into input suitable for weka.')
    parser.add_argument('--new', action='store_true', help='Parses the raw plaintext trace file into input suitable for new feature extractor.')
    parser.add_argument('--src', default="./data", help='Source directory containing the plaintext data to parse. Deaults to ./data.')
    parser.add_argument('--src2', default="./output", help='Secondary source directory containing the plaintext data to parse. Deaults to ./file.')
    parser.add_argument('--dst', default="./pre-processed", help='Destination directory to store parsed data. Defaults to ./pre-processed.')
    parser.add_argument('--check_new',action='store_true', help='Parses the raw plaintext trace file into input suitable for new feature extractor.')
    parser.add_argument('--noremove',action='store_true', help='Calculates total number of corrupted data files instead of removal.')
    parser.add_argument('--fix_new',action='store_true', help='Re-calculates starttime, endtime and timestamp for corrupted files.')
    parser.add_argument('--filter_len', nargs=1, metavar="INT", default=1000, help='Length of packet filter. Packets with length less than this will be filtered out.')
    parser.add_argument('--test_func', action='store_true', help='Test result of helper function.')

    args = parser.parse_args()

    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    if args.src:
        src_dir=str(args.src)
        # check if source directory exists
        if not os.path.exists(src_dir):
            print_dbg_msg_L1("[+] Source directory " + src_dir + " does not exist. Please try again!")
        dst_dir=str(args.dst)
        if not os.path.exists(dst_dir):
            print_dbg_msg_L1("[+] Destination  directory " + dst_dir + " does not exist. Please try again!")

    if args.src2:
        src_dir_2=str(args.src2)

    if dst_dir:
        dst_dir=str(args.dst)

    if args.k:
        # tor
        parse_for_k_fingerprinting()
    elif args.weka:
        # normal
        parse_for_weka()
    elif args.new:
        if args.filter_len:
            parse_for_new(args.filter_len[0])
    elif args.check_new:
        check_new()
    elif args.fix_new:
        fix_new()
    elif args.test_func:
        print_dbg_msg_L1("[+] Starting test...")
        dummy_func()