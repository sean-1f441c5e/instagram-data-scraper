import sys

if len(sys.argv) < 4:
    print "Usage: extract_features.py <source> <num websites> <num trials> [optional: <num other train> <num open world>]"
    exit(0)

"""
This code was derived from Wang et al's Usenix Security 2014 code base.
This generates an arff file that can be used with Weka.
Generates the training data <source>.arff, and the test data <source>_ow.arff.
Input:
source - source directory
num websites - number of sensitive websites
num trials - number of instances of sensitive websites
num other train - number of insensitive websites to train on
num open world - number of open world websites
"""

src_dir  = sys.argv[1]
num_web  = int(sys.argv[2])
num_inst = int(sys.argv[3])

if len(sys.argv) > 4:
    num_others = int(sys.argv[4])
else:
    num_others = 0

num_inst_start = 0

if len(sys.argv) > 5:
    num_ow = int(sys.argv[5])
else:
    num_ow = 0

max_count = 100

#time and direction
def extract(times, dirs):

    features = []

    size = len(times)

    features.append(size) #num packets
    features.append(len([d for d in dirs if d > 0])) #num outgoing
    features.append(len([d for d in dirs if d < 0])) #num incoming
    features.append(times[-1] - times[0]) #transmission time

    #locations of outgoing packets
    count = 0
    for i in range(0, size):
        if dirs[i] > 0:
            features.append(i)
            count += 1
        if count >= max_count:
            break
    for i in range(count, max_count):
        features.append(-1)

    #burst of incoming packets
    count = 0
    prevloc = 0
    for i in range(0, len(dirs)):
        if dirs[i] > 0:
            count += 1
            features.append(i - prevloc)
            prevloc = i
        if count == max_count:
            break
    for i in range(count, max_count):
        features.append(-1)

    #burst of outgoing packets
    bursts = []
    curburst = 0
    stopped = 0
    for x in dirs:
        if x < 0:
            stopped = 0
            curburst -= x
        if x > 0 and stopped == 0:
            stopped = 1
        if x > 0 and stopped == 1:
            stopped = 0
            bursts.append(curburst)
    features.append(max(bursts))
    features.append(sum(bursts)/len(bursts))
    features.append(len(bursts))
    counts = [0, 0, 0]
    for x in bursts:
        if x > 5:
            counts[0] += 1
        if x > 10:
            counts[1] += 1
        if x > 15:
            counts[2] += 1
    features.append(counts[0])
    features.append(counts[1])
    features.append(counts[2])

    return features

'''
Extract the features from the raw data. 

ext_sites - number of sensitive sites in data
ext_start - base index
ext_num - number of instances of sensitive sites
ow - boolean flag to indicate open world training
num_others - insensitive websites used for training
'''
def extract_all(ext_sites, ext_start, ext_num, ow, num_others=0):
    all_features = []
    #this takes quite a while
    for site in range(0, ext_sites+num_others):
        #print site
        range_low = ext_start
        if ow or site >= ext_sites:
            range_high = 1
        else:
            range_high = ext_start + ext_num
        for instance in range(range_low, range_high):
            if ow or site >= ext_sites:
                fname = str(site)
            else:
                fname = str(site) + "-" + str(instance)
            #Set up times, dirs
            try:
                f = open('%s/%s' % (src_dir, fname), 'r')
                times = []
                dirs = []
                for x in f:
                    x = x.split("\t")
                    times.append(float(x[0]))
                    dirs.append(int(x[1]))
                f.close()
                #Extract features. All features are non-negative numbers or X.
                features = extract(times, dirs)
                features.append(site)
                all_features.append(features)
            except:
                print "[extract_all] Unable to open %s/%s" % (src_dir, fname)
    return all_features

def generate_arff(all_features, ow):

    header = ['%Training set for binary classifier \n@RELATION hidden_service\n']

    attribute = '@ATTRIBUTE %s %s\n'

    footer = '\n@DATA\n'

    num_feat = len(all_features[0])

    for i in range(num_feat-1):
        header.append(attribute % ('feat' + str(i), 'NUMERIC'))

    web_class = []
    for i in range(num_web):
        web_class.append('web' + str(i))
    web_class.append('other')
    header.append('@ATTRIBUTE %s {%s}\n' % ('feat' + str(num_feat), ','.join(web_class)))


    header.append(footer)

    if ow:
        feature_file = open(src_dir + '_ow.arff', 'w')
    else:
        feature_file = open(src_dir + '.arff', 'w')
    feature_file.write(''.join(header))
    for features in all_features:
        assert(num_feat == len(features))
        for x in features[:-1]:
            feature_file.write(repr(x) + ', ')
        if features[-1] < num_web:
            feature_file.write('web' + str(features[-1]))
        else:
            feature_file.write('other')
        feature_file.write('\n')
    feature_file.close()


all_features = extract_all(num_web, num_inst_start, num_inst, False, num_others)
generate_arff(all_features, False)

if num_ow == 0:
    exit(0)

all_features = extract_all(num_ow, 0, 1, True)
generate_arff(all_features, True)
