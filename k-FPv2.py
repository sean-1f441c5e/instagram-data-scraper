import csv
import sys
from sys import stdout
import RF_fextract
import numpy as np
#import matplotlib.pylab as plt
import operator
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score
from sklearn import metrics
from sklearn import tree
import sklearn.metrics as skm
import scipy
import dill
import random
import os
from collections import defaultdict
import argparse
from itertools import chain
#from tqdm import *

# re-seed the generator
#np.random.seed(1234)

### Paths to data ###

rootdir = r"../data/"
alexa_monitored_data = rootdir + r"Alexa_Monitored/"
hs_monitored_data = rootdir + r"HS_Monitored/"
insta_monitored_data = rootdir + r"Insta_Monitored/"
insta_tor_monitored_data = rootdir + r"Insta_Tor_Monitored/"
new_monitored_data = rootdir + r"New_Monitored/"
#monitored_data = rootdir + r"Monitored/"
unmonitored_data = rootdir + r"Unmonitored/"
dic_of_feature_data = rootdir + r"Features"


### Parameters ###
# Number of sites, number of instances per site, number of (alexa/hs) monitored training instances per site, Number of trees for RF etc.

alexa_sites = 55
alexa_instances = 100
alexa_train_inst = 60

hs_sites = 30
hs_instances = 100
hs_train_inst = 60

insta_sites = 50
insta_instances = 100
insta_train_inst = 60

insta_tor_sites = 50
insta_tor_instances = 100
insta_tor_train_inst = 60

new_sites = 50
new_instances = 100
new_train_inst = 60
#assert alexa_instances == hs_instances
#assert alexa_train_inst == hs_train_inst
mon_train_inst = alexa_train_inst
mon_test_inst = alexa_instances - mon_train_inst

num_Trees = 1000

unmon_total = 100000
unmon_train = 5000


############ Feeder functions ############

def chunks(l, n):
    """ Yield successive n-sized chunks from l."""
    for i in xrange(0, len(l), n):
        yield l[i:i+n]

def checkequal(lst):
    return lst[1:] == lst[:-1]


############ Non-Feeder functions ########

dict_build_flags = {'build_alexa': True,
                    'build_hs': True,
                    'build_insta': True,
                    'build_insta_tor': True,
                    'build_unmon': True,
                    'build_new': True}

def test_dictionary_(path_to_dict = dic_of_feature_data, path_to_alexa = alexa_monitored_data, path_to_hs = hs_monitored_data, path_to_unmon = unmonitored_data,
                alexa_sites = alexa_sites, alexa_instances = alexa_instances, hs_sites = hs_sites, hs_instances = hs_instances, unmon_sites = unmon_total):
    '''Extract Features -- A dictionary containing features for each traffic instance.'''

    dic_of_feature_data = path_to_dict

    data_dict = {'alexa_feature': [],
                 'alexa_label': [],
                 'hs_feature': [],
                 'hs_label': [],
                 'insta_feature': [],
                 'insta_label': [],
                 'insta_tor_feature': [],
                 'insta_tor_label': [],
                 'new_feature': [],
                 'new_label': [],
                 'unmonitored_feature': [],
                 'unmonitored_label': []}

    path_to_insta = insta_monitored_data

    print "Creating Insta features..."
    for i in range(0, insta_sites):
        for j in range(1, insta_instances+1):
            fname = str(i) + "_" + str(j)
            if not os.path.exists(path_to_insta + fname):
                print "Unable to find file " + path_to_insta + fname
        print i

    path_to_insta_tor = insta_tor_monitored_data

    print "Creating Insta Tor features..."
    for i in range(0, insta_tor_sites):
        for j in range(0, insta_tor_instances):
            fname = str(i) + "_" + str(j)
            if not os.path.exists(path_to_insta_tor + fname):
                print "Unable to find file " + path_to_insta_tor + fname
        print i

    path_to_new = new_monitored_data

    print "Creating New features..."
    for i in range(1, new_sites+1):
        for j in range(0, new_instances):
            fname = str(i) + "_" + str(j)
            if not os.path.exists(path_to_new + fname):
                print "Unable to find file " + path_to_new + fname
        print i


def dictionary_(path_to_dict = dic_of_feature_data, path_to_alexa = alexa_monitored_data, path_to_hs = hs_monitored_data, path_to_unmon = unmonitored_data,
                alexa_sites = alexa_sites, alexa_instances = alexa_instances, hs_sites = hs_sites, hs_instances = hs_instances, unmon_sites = unmon_total):
    '''Extract Features -- A dictionary containing features for each traffic instance.'''

    dic_of_feature_data = path_to_dict

    data_dict = {'alexa_feature': [],
                 'alexa_label': [],
                 'hs_feature': [],
                 'hs_label': [],
                 'insta_feature': [],
                 'insta_label': [],
                 'insta_tor_feature': [],
                 'insta_tor_label': [],
                 'new_feature': [],
                 'new_label': [],
                 'unmonitored_feature': [],
                 'unmonitored_label': []}

    if dict_build_flags['build_alexa'] == True:
        print "Creating Alexa features..."
        for i in range(alexa_sites):
            for j in range(alexa_instances):
                fname = str(i) + "_" + str(j)
                if os.path.exists(path_to_alexa + fname):
                    tcp_dump = open(path_to_alexa + fname).readlines()
                    g = []
                    g.append(RF_fextract.TOTAL_FEATURES(tcp_dump))
                    data_dict['alexa_feature'].append(g)
                    data_dict['alexa_label'].append((i,j))
            print i

    if dict_build_flags['build_hs'] == True:
        print "Creating HS features..."
        for i in range(1, hs_sites + 1):
            for j in range(hs_instances):
                fname = str(i) + "_" + str(j) + ".txt"
                if os.path.exists(path_to_hs + fname):
                    tcp_dump = open(path_to_hs + fname).readlines()
                    g = []
                    g.append(RF_fextract.TOTAL_FEATURES(tcp_dump))
                    data_dict['hs_feature'].append(g)
                    data_dict['hs_label'].append((i,j))
            print i
    
    path_to_insta = insta_monitored_data

    if dict_build_flags['build_insta'] == True:
        print "Creating Insta features..."
        for i in range(0, insta_sites):
            for j in range(1, insta_instances+1):
                fname = str(i) + "_" + str(j)
                if os.path.exists(path_to_insta + fname):
                    tcp_dump = open(path_to_insta + fname).readlines()
                    g = []
                    g.append(RF_fextract.TOTAL_FEATURES(tcp_dump))
                    data_dict['insta_feature'].append(g)
                    data_dict['insta_label'].append((i,j))
                else:
                    print "Unable to find file " + path_to_insta + fname
            print i

    path_to_insta_tor = insta_tor_monitored_data

    if dict_build_flags['build_insta_tor'] == True:
        print "Creating Insta Tor features..."
        for i in range(0, insta_tor_sites):
            for j in range(0, insta_tor_instances):
                fname = str(i) + "_" + str(j)
                if os.path.exists(path_to_insta_tor + fname):
                    tcp_dump = open(path_to_insta_tor + fname).readlines()
                    g = []
                    g.append(RF_fextract.TOTAL_FEATURES(tcp_dump))
                    data_dict['insta_tor_feature'].append(g)
                    data_dict['insta_tor_label'].append((i,j))
                else:
                    print "Unable to find file " + path_to_insta_tor + fname
            print i

    path_to_new = new_monitored_data

    if dict_build_flags['build_new'] == True:
        print "Creating New features..."
        for i in range(1, new_sites+1):
            for j in range(0, new_instances):
                fname = str(i) + "_" + str(j)
                try:
                    if os.path.exists(path_to_new + fname):
                        tcp_dump = open(path_to_new + fname).readlines()
                        g = []
                        g.append(RF_fextract.TOTAL_FEATURES(tcp_dump))
                        data_dict['new_feature'].append(g)
                        data_dict['new_label'].append((i,j))
                    else:
                        print "Unable to find file " + path_to_new + fname
                except Exception as e:
                    print "Error occurred at %s\n" % fname
                    print e
                    raise
            print i

    if dict_build_flags['build_unmon'] == True:
        print "Creating Unmonitored features..."
        d, e = alexa_sites + 1, 0
        print "Max unmon_sites: " + str(unmon_sites)
        while e < unmon_sites:
            if e%100 == 0  and e>0:
                print e
            if os.path.exists(path_to_unmon + str(d)):
                tcp_dump = open(path_to_unmon + str(d)).readlines()
                g = []
                g.append(RF_fextract.TOTAL_FEATURES(tcp_dump))
                data_dict['unmonitored_feature'].append(g)
                data_dict['unmonitored_label'].append((d))
                d += 1
                e += 1
            else:
                d += 1

    print "Extraction complete, writing to file [" + dic_of_feature_data + "] ..."
    if dict_build_flags['build_alexa'] == True:
        assert len(data_dict['alexa_feature']) == len(data_dict['alexa_label'])
    if dict_build_flags['build_hs'] == True:
        assert len(data_dict['hs_feature']) == len(data_dict['hs_label'])
    if dict_build_flags['build_insta'] == True:
        assert len(data_dict['insta_feature']) == len(data_dict['insta_label'])
    if dict_build_flags['build_insta_tor'] == True:
        assert len(data_dict['insta_tor_feature']) == len(data_dict['insta_tor_label'])
    if dict_build_flags['build_new'] == True:
        assert len(data_dict['new_feature']) == len(data_dict['new_label'])
    if dict_build_flags['build_unmon'] == True:
        assert len(data_dict['unmonitored_feature']) == len(data_dict['unmonitored_label'])
    fileObject = open(dic_of_feature_data,'wb')
    dill.dump(data_dict,fileObject)
    fileObject.close()
    print "Extraction commplete!"


def mon_train_test_references(mon_type, path_to_dict = dic_of_feature_data):
    """Prepare monitored data in to training and test sets."""

    fileObject1 = open(path_to_dict,'r')
    dic = dill.load(fileObject1)

    if mon_type == 'alexa':
        split_data = list(chunks(dic['alexa_feature'], alexa_instances))
        split_target = list(chunks(dic['alexa_label'], alexa_instances))
    elif mon_type == 'hs':
        split_data = list(chunks(dic['hs_feature'], hs_instances))
        split_target = list(chunks(dic['hs_label'], hs_instances))
    elif mon_type == 'insta':
        split_data = list(chunks(dic['insta_feature'], insta_instances))
        split_target = list(chunks(dic['insta_label'], insta_instances))
    elif mon_type == 'insta_tor':
        split_data = list(chunks(dic['insta_tor_feature'], insta_tor_instances))
        split_target = list(chunks(dic['insta_tor_label'], insta_tor_instances))
    elif mon_type == 'new':
        split_data = list(chunks(dic['new_feature'], new_instances))
        split_target = list(chunks(dic['new_label'], new_instances))

    training_data = []
    training_label = []
    test_data = []
    test_label = []
    for i in range(len(split_data)):
        temp = zip(split_data[i], split_target[i])
        random.shuffle(temp)
        data, label = zip(*temp)
        training_data.extend(data[:mon_train_inst])
        training_label.extend(label[:mon_train_inst])
        test_data.extend(data[mon_train_inst:])
        test_label.extend(label[mon_train_inst:])

    flat_train_data = []
    flat_test_data = []
    for tr in training_data:
        flat_train_data.append(list(sum(tr, ())))
    for te in test_data:
        flat_test_data.append(list(sum(te, ())))
    training_features =  zip(flat_train_data, training_label)
    test_features =  zip(flat_test_data, test_label)
    return training_features, test_features

def unmon_train_test_references(path_to_dict = dic_of_feature_data):
    """Prepare unmonitored data in to training and test sets."""

    fileObject1 = open(path_to_dict,'r')
    dic = dill.load(fileObject1)

    training_data = []
    training_label = []
    test_data = []
    test_label = []

    unmon_data = dic['unmonitored_feature']
    unmon_label = [(101, i) for i in dic['unmonitored_label']]
    unmonitored = zip(unmon_data, unmon_label)
    random.shuffle(unmonitored)
    u_data, u_label = zip(*unmonitored)

    training_data.extend(u_data[:unmon_train])
    training_label.extend(u_label[:unmon_train])

    test_data.extend(u_data[unmon_train:unmon_total])
    test_label.extend(u_label[unmon_train:unmon_total])

    flat_train_data = []
    flat_test_data = []
    for tr in training_data:
        flat_train_data.append(list(sum(tr, ())))
    for te in test_data:
        flat_test_data.append(list(sum(te, ())))
    training_features =  zip(flat_train_data, training_label)
    test_features =  zip(flat_test_data, test_label)
    return training_features, test_features


def RF_closedworld(mon_type, path_to_dict = dic_of_feature_data):
    '''Closed world RF classification of data -- only uses sk.learn classification - does not do additional k-nn.'''

    training, test = mon_train_test_references(mon_type, path_to_dict)
    tr_data, tr_label1 = zip(*training)
    tr_label = zip(*tr_label1)[0]
    te_data, te_label1 = zip(*test)
    te_label = zip(*te_label1)[0]

    print "Monitored type: ", mon_type
    print

    print "Training ..."
    ''' 
    Uses the random forst classifier. The defaults used here:
        - 2 parallel jobs
        - 1000 trees in forest used to classifer
        - use out-of-bag score
    According to the documentation, "The features are always randomly permuted at each split.".
    By taking average run results over many iterations, it should be possible to derive an
    average of runtimes and classification accuracy.
    '''
    model = RandomForestClassifier(n_jobs=4, n_estimators=num_Trees, oob_score = True)
    model.fit(tr_data, tr_label)
    print "RF accuracy = ", model.score(te_data, te_label)

    #print "Feature importance scores:"
    #print model.feature_importances_

    scores = cross_val_score(model, np.array(tr_data), np.array(tr_label))
    print "cross_val_score = ", scores.mean()
    #print "OOB score = ", model.oob_score_(tr_data, tr_label)


def RF_openworld(mon_type, path_to_dict = dic_of_feature_data):
    '''Produces leaf vectors used for classification.'''

    mon_training, mon_test = mon_train_test_references(mon_type, path_to_dict)
    unmon_training, unmon_test = unmon_train_test_references(path_to_dict)

    training = mon_training + unmon_training
    test = mon_test + unmon_test

    tr_data, tr_label1 = zip(*training)
    tr_label = zip(*tr_label1)[0]
    te_data, te_label1 = zip(*test)
    te_label = zip(*te_label1)[0]

    print "Training ..."
    model = RandomForestClassifier(n_jobs=-1, n_estimators=num_Trees, oob_score=True)
    model.fit(tr_data, tr_label)

    train_leaf = zip(model.apply(tr_data), tr_label)
    test_leaf = zip(model.apply(te_data), te_label)
    return train_leaf, test_leaf


def distances(mon_type, path_to_dict = dic_of_feature_data, keep_top=100):
    """ This uses the above function to calculate distance from test instance 
        between each training instance (which are used as labels) and writes to file
        Default keeps the top 100 instances closest to the instance we are testing.
        -- Saves as (distance, true_label, predicted_label) --
    """

    train_leaf, test_leaf = RF_openworld(mon_type, path_to_dict)

    direc = rootdir
    if not os.path.exists(direc):
        os.mkdir(direc)
    monitored_directory = rootdir + "/" + mon_type + "-monitored-distances/"
    if not os.path.exists(monitored_directory):
        os.mkdir(monitored_directory)
    unmonitored_directory = rootdir + "/" + mon_type + "-unmonitored-distances/"
    if not os.path.exists(unmonitored_directory):
        os.mkdir(unmonitored_directory)

    # Make into numpy arrays
    train_leaf = [(np.array(l, dtype=int), v) for l, v in train_leaf]
    test_leaf = [(np.array(l, dtype=int), v) for l, v in test_leaf]

    if mon_type == 'alexa':
        sites = alexa_sites
    elif mon_type == 'hs':
        sites = hs_sites

    for i, instance in enumerate(test_leaf[:(mon_test_inst*sites)]):
        if i%100==0:
            stdout.write("\r%d out of %d" %(i, mon_test_inst*sites))
            stdout.flush()

        temp = []
        for item in train_leaf:
            # vectorize the average distance computation
            d = np.sum(item[0] != instance[0]) / float(item[0].size)
            if d == 1.0:
                continue
            temp.append((d, instance[1], item[1]))
        tops = sorted(temp)[:keep_top]
        myfile = open(monitored_directory  + '%d_%s.txt' %(instance[1], i), 'w')
        for item in tops:
            myfile.write("%s\n" % str(item))
        myfile.close()

    for i, instance in enumerate(test_leaf[(mon_test_inst*sites):]):
        if i%100==0:
            stdout.write("\r%d out of %d" %(i, len(test_leaf)-mon_test_inst*sites))
            stdout.flush()

        temp = []
        for item in train_leaf:
            # vectorize the average hamming distance computation
            d = np.sum(item[0] != instance[0]) / float(item[0].size)
            if d == 1.0:
                continue
            temp.append((d, instance[1], item[1]))
        tops = sorted(temp)[:keep_top]
        myfile = open(unmonitored_directory  + '%d_%s.txt' %(instance[1], i), 'w')
        for item in tops:
            myfile.write("%s\n" % str(item))
        myfile.close()


def distance_stats(mon_type, rootdir, knn=3):
    """
        For each test instance this picks out the minimum training instance distance, checks (for mon) if it is the right label and checks if it's knn are the same label
    """

    monitored_directory = rootdir + "/" + mon_type + "-monitored-distances/"
    unmonitored_directory = rootdir + "/" + mon_type + "-unmonitored-distances/"

    TP=0
    for subdir, dirs, files in os.walk(monitored_directory):
        for file in files:
            fn = os.path.join(subdir, file)
            data = open(str(fn)).readlines()
            internal_count = 0
            for i in data[:knn]:
                distance = float(eval(i)[0])
                true_label = float(eval(i)[1])
                predicted_label = float(eval(i)[2])
                if true_label == predicted_label:
                    internal_count += 1
            if internal_count == knn:
                TP+=1
    path, dirs, files = os.walk(monitored_directory).next()
    file_count1 = len(files)
    print "TP = ", TP/float(file_count1)

    FP = 0
    for subdir, dirs, files in os.walk(unmonitored_directory):
        for file in files:
            fn = os.path.join(subdir, file)
            data = open(str(fn)).readlines()
            internal_count = 0
            test_list = []
            internal_test = []
            for i in data[:knn]:
                distance = float(eval(i)[0])
                true_label = float(eval(i)[1])
                predicted_label = float(eval(i)[2])
                internal_test.append(predicted_label)
            if checkequal(internal_test) == True and internal_test[0] <= alexa_sites:
                FP+=1

    path, dirs, files = os.walk(unmonitored_directory).next()
    file_count2 = len(files)
    print "FP = ", FP/float(file_count2)
    return TP/float(file_count1), FP/float(file_count2)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='k-FP benchmarks')
    parser.add_argument('--test_dictionary', action='store_true', help='Test dictionary for instagram data set')
    parser.add_argument('--dictionary', action='store_true', help='Build dictionary.')
    parser.add_argument('--RF_closedworld', action='store_true', help='Closed world classification.')
    parser.add_argument('--distances', action='store_true', help='Build distances for open world classification.')
    parser.add_argument('--distance_stats', action='store_true', help='Open world classification.')
    parser.add_argument('--knn', nargs=1, metavar="INT", help='Number of nearest neighbours.')
    parser.add_argument('--mon_type', nargs=1, metavar="STR", help='The type of monitored dataset - alexa, hs, insta, insta_tor or new')
    parser.add_argument('--single_dict', nargs=1, metavar="STR", help='Only builds the dictionary with a single dataset')

    args = parser.parse_args()

    if args.dictionary:

        # Example command line:
        # $ python k-FP.py --dictionary
        if args.single_dict:
            print("[+] Building dictionary with " + str(args.single_dict[0]))
            for flag in dict_build_flags:
                if flag.endswith(str(args.single_dict[0])):
                    dict_build_flags[flag] = True
                else:
                    dict_build_flags[flag] = False
                print("\t[+] " + flag + ": " + str(dict_build_flags[flag]))

        dictionary_()

    elif args.test_dictionary:

        test_dictionary_()

    elif args.RF_closedworld:

        # Example command line:
        # $ python k-FP.py --RF_closedworld --mon_type alexa

        mon_type = str(args.mon_type[0])

        RF_closedworld(mon_type)

    elif args.distances:

        # Example command line:
        # $ python k-FP.py --distances --mon_type alexa

        mon_type = str(args.mon_type[0])

        distances(mon_type, path_to_dict = dic_of_feature_data, keep_top=100)

    elif args.distance_stats:

        # Example command line:
        # $ python k-FP.py --distance_stats --knn 6 --mon_type hs

        knn = int(args.knn[0])
        mon_type = str(args.mon_type[0])

        distance_stats(mon_type, rootdir, knn)
