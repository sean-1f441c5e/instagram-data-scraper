from selenium import webdriver
import tbselenium.common as cm
from tbselenium.tbdriver import TorBrowserDriver
from tbselenium.utils import launch_tbb_tor_with_stem
from pyvirtualdisplay import Display
import subprocess
import shlex
import time
import random
import argparse
import os
import operator
import sys
import shutil
import secrets

##############################
# CHANGE THESE SETTINGS ONLY #
##############################

# Source file to extract user profile names from, assumed to be 1 username per line
src_file="./top50.txt"

# Target website to scrap. This works by concatenating 
# <targetsite_base>/<username_from_src_file>
targetsite_base="https://www.instagram.com/"

# The directory to drop all the collected data
dump_location=os.path.expandvars("$PWD/data/")

# Originally meant to enable to disable various levels of debug messages, now 
# it just turns debug messages on or off
debug_msg_lvl=1

# Directory where the Tor Browser Bundle is extracted to. Using the expandvars()
# function here just in case environmental variables such as $PWD or $HOME is used
tbb_dir=os.path.expandvars("/home/user/Desktop/Project/tor-browser_en-US/")

# Default user profile. YOu have a very specific need for different user profiles, 
# is is recommended to keep this setting as it is.
tbb_ff_default_dir=os.join(tbb_dir, "TorBrowser/Data/Browser/profile.default")

# The directory where the Tor browser dumps its logs. This is useful if you are
# troubleshooting connection issues with Tor
tbb_log_dir=os.path.expandvars("$PWD/logs/tbb_log.txt")

# Ensures browser instances are hidden.
hide_display=1

# Enables the ability to resume scraping from last known good collection. 
# Disable to collect from scratch. 
resume=1

# Directory to dump the various files used for Chrome instnaces. 
chrome_debug_profile=os.path.expandvars("$PWD/logs/chrome-profiling")

# Maximum number of instances to collect per user
max_runs=100

###############################################################################

class bcolors:
    """bcolors: Ascii color coding class.

    This is used by print_dbg_msg_L1() to print pretty colours. While there are 
    many colour codings available, print_dbg_msg_L1 currently only uses GREEN.
    """
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


###############################################################################

def print_dbg_msg_L1(msg: str) -> None:
    """Prints the message passed in.

    Whether the message gets displayed depends on the global flag debug_msg_lvl.
    Currently this function will print any message passed in, because
    debug_msg_lvl is set to 1.

    Args:
        param1: The message to print.

    Returns:
        None: No values are returned.

    """
    if (debug_msg_lvl >= 1):
        print bcolors.OKGREEN + msg + bcolors.ENDC


###############################################################################

class WebBrowserType:
    """WebBrowserType: Browser type labelling class.

    This is used represent the various browser types using numeric values instead
    of string values. This to allow for easy checking and changing/expanding of 
    values.
    """
    FIREFOX = 0
    CHROME = 1
    CHROME_DEBUG = 2
    TOR = 3

class InstagramScraper():
    """InstagramScraper: Web scraper class.

    This class is used represent the various browser types using numeric values instead
    of string values. This to allow for easy checking and changing/expanding of 
    values.
    """
    def __init__(self, browser_type, user_data_dir=None):
        # internal flag so we know what sort of web browser we are instantiating
        self.WebBrowserType = browser_type 

        # various browser initiation according to different browser types
        if (browser_type == WebBrowserType.CHROME):
            print_dbg_msg_L1("\t[+] Starting Chrome...")
            options = webdriver.chrome.options.Options()
            options.add_argument("--headless")
            options.add_argument("--disable-gpu")
            options.add_argument("--no-sandbox")
            options.add_argument("--no-default-browser-check")
            self.browser = webdriver.Chrome(chrome_options=options)
        elif (browser_type == WebBrowserType.CHROME_DEBUG):
            print_dbg_msg_L1("\t[+] Starting Chrome in debug mode...")
            options = webdriver.chrome.options.Options()
            options.add_argument("--headless")
            options.add_argument("--disable-gpu")
            options.add_argument("--no-sandbox")
            options.add_argument("--no-default-browser-check")
            options.add_argument("--remote-debugging-port=9222")
            if user_data_dir == None:
                user_data_dir=chrome_debug_profile + "/" + str(secrets.token_hex(16))
            #print_dbg_msg_L1("\t\t[+] User data dir: " + user_data_dir)
            if not os.path.exists(user_data_dir):
                os.makedirs(user_data_dir)
            options.add_argument("--user-data-dir=" + user_data_dir)
            self.browser = webdriver.Chrome(chrome_options=options)
        elif (browser_type == WebBrowserType.TOR):
            ''' 
            Sometimes the Tor process fails to launch or the web browser fails
            to instantiate properly. Regardless, loop until both the Tor
            process and the browser is instantiated correctly. So far, over
            30,000 runs, the instantiation usually kicks in after at most 1
            failure.
            
            '''
            while True:
                try:
                    self.tor_process = launch_tbb_tor_with_stem(tbb_path=tbb_dir)
                    self.browser = TorBrowserDriver(tbb_dir, \
                        tor_cfg=cm.USE_STEM, \
                        tbb_profile_path=tbb_ff_default_dir, \
                        tbb_logfile_path=tbb_log_dir)
                except Exception as e:
                    print_dbg_msg_L1("\t[+] " + str(e))
                    print_dbg_msg_L1("\t[+] Error instantiating browser, retrying...")
                    time.sleep(1)
                    continue
                else:
                    break   
        else:
            self.browser = webdriver.Firefox()

    def get(self, targetWebAddress):
        self.browser.get(targetWebAddress)

    def close(self):
        self.browser.quit()
        if self.WebBrowserType == WebBrowserType.TOR:
            self.tor_process.kill()

    def __exit__(self, exc_type, exc_value, traceback):
        self.browser.quit()

###############################################################################

def get_ip():
    GET_IP_CMD ="hostname -I"
    return subprocess.check_output(GET_IP_CMD, shell=True).decode('utf-8') 

def check_resume_point(data_dir):
    data_files = os.listdir(data_dir)

    user_index = 0
    run_index = 0
    file_list = []

    for data_file in data_files:
        # only process data files
        if data_file.endswith(".txt"):
            file_name = data_file.split("_")
            file_list.append([int(file_name[0]), int(file_name[1].split(".")[0])])

    if len(file_list) > 0:
        file_list.sort(key = operator.itemgetter(0), reverse=True)
        file_list.sort(key = operator.itemgetter(1), reverse=True)
    else:
        file_list.append([0,0])

    print_dbg_msg_L1("[+] Restart from user/level: " + str(file_list[0][0]) + " / " + str(file_list[0][1]))
    
    return file_list[0]

def run_script():
    return

def scrap_for_data(scrap_type):
    print_dbg_msg_L1("[+] Reading from file...")
    top50 = [line.rstrip('\n') for line in open(src_file)]

    # creates a virtual display so that we don't get the browsers popping in and 
    # out
    display = ""
    if (hide_display == 1):
        print_dbg_msg_L1("[+] Setting display...")
        display = Display(visible=0, size=(1920, 1080))
        display.start()

    starttime = time.time()
    ip_addr = get_ip()
    scraper = ""
    resume_index = check_resume_point(dump_location)
    print_dbg_msg_L1("resume_index: " + str(resume_index[0]))
    resume_run = resume

    if (resume_run == 0):
        base = 0
    else:
        base = resume_index[1]
        #print_dbg_msg_L1("[+] Resuming from run " + str(base) + ", user " + str(resume_index[0]))
    
    if scrap_type == WebBrowserType.CHROME_DEBUG:
        max_runs = 1

    try:
        for counter in range(base,max_runs):
            for user in top50:
                # if resume is required, skip until the resume point
                if (resume_run == 1):
                    if top50.index(user) == resume_index[0]:
                        resume_run = 0
                    else:
                        print_dbg_msg_L1("\t[+] Skipping " + str(top50.index(user)))
                        continue

                if scrap_type == WebBrowserType.CHROME_DEBUG:
                    user_data_dir=chrome_debug_profile + "/" + str(top50.index(user)) + "/"

                # craft command to start pcap
                pcap_logfile= "%s%d_%d.pcap" % (dump_location, top50.index(user), counter)
                tcpdump_cmd = "tcpdump 'tcp and host " + ip_addr + "' -ttttt -nn -U -w " + pcap_logfile

                # start tcpdump
                print_dbg_msg_L1("\t[+] starting tcpdump...")
                p = subprocess.Popen(shlex.split(tcpdump_cmd))
                #sleep_int = random.uniform(1.0,2.0)
                #print_dbg_msg_L1("\t[+] " + str(sleep_int) + "s before commencing...")
                #time.sleep(sleep_int)

                # instantiate scraper
                print_dbg_msg_L1("\t[+] Starting browser...")
                if scrap_type ==  WebBrowserType.CHROME_DEBUG:
                    scraper = InstagramScraper(scrap_type, user_data_dir)
                else:
                    scraper = InstagramScraper(scrap_type)

                runtime = time.time()
                print_dbg_msg_L1("[+] Starting run for " + str(user) + ": " + str(top50.index(user)) + " / " + str(counter))
                # craft correct site
                site = targetsite_base + user

                # start selenium browser
                print_dbg_msg_L1("\t[+] starting browser get...")
                scraper.get(site)
                print_dbg_msg_L1("\t[+] browser get complete!")

                # kill the pcap PID
                time.sleep(3)
                print_dbg_msg_L1("\t[+] Killing tcpdump...")
                p.kill()

                # convert pcap file into plain text
                pcap_plaintext= "%s%d_%d.pcap.txt" % (dump_location, top50.index(user), counter)
                tcpdump_r_cmd = shlex.split("tcpdump -ttttt -nn -r " + pcap_logfile)
                print_dbg_msg_L1("\t[+] Creating plaintext logfile...")
                logfile = open(pcap_plaintext, "w")
                print_dbg_msg_L1("\t[+] Starting pcap conversion...")
                p_r = subprocess.Popen(tcpdump_r_cmd, stdout=logfile)
                p_r.wait()
                logfile.close()

                # close driver
                print_dbg_msg_L1("[+] Closing browser...")
                scraper.close()

                print_dbg_msg_L1("[+] Run complete! " + str(time.time() - runtime) + "s taken")
                #print_dbg_msg_L1("[+] " + str(sleep_int) + "s before next round...\n")
                #time.sleep(sleep_int)

            # tmp folder can quickly ballon out of control, so we purge every 50 runs
            print_dbg_msg_L1("[+] Routine purging of /tmp to keep size manageable...")
            for f in os.listdir("/tmp"):
                if os.path.isdir("/tmp/" + f):
                    if f.startswith("tmp"):
                        shutil.rmtree("/tmp/" + f)
            print_dbg_msg_L1("[+] Done!")

    finally:
        if (hide_display):
            display.stop()
        if (scraper):
            scraper.close()

    print_dbg_msg_L1("\n[+] Total time taken: " + str(time.time() - starttime) + "s\n")

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='k-FP benchmarks')
    parser.add_argument('--normal', action='store_true', help='Scraps Instagram for data using normal browser.')
    parser.add_argument('--tor', action='store_true', help='Scraps Instagram for data using tor browser.')
    parser.add_argument('--chrome_debugging', action='store_true', help='Runs Chrome in debugging mode.')

    args = parser.parse_args()

    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    if args.tor:
        # tor
        scrap_for_data(3)
    elif args.normal:
        # normal
        scrap_for_data(1)
    elif args.chrome_debugging:
        # run with chrome in debug mode
        scrap_for_data(2)