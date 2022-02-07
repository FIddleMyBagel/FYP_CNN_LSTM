import os
import json
import subprocess as sp
import numpy as np
import tensorflow as tf
import csv
import random
import glob
import concurrent.futures
from collections import Counter

directory = "/home/fyp/Desktop/cnn/pcaps/"
output_dir = "data"
filename_list = [i.replace(".pcap", "").replace(directory, "") for i in glob.glob(directory + '*.pcap')]
classes = {0:["BENIGN"], 1:["FTP-Patator"], 2:["SSH-Patator"], 3:["DoS GoldenEye"], 4:["DoS Hulk"], 5:["DoS Slowhttptest"], 6:["DoS slowloris"], 7:["Web Attack ñ Brute Force", "Web Attack ñ Sql Injection", "Web Attack ñ XSS"], 8:["Bot"], 9:["DDoS"], 10:["PortScan"]}
distribution = [0.5, 0.03, 0.03, 0.03, 0.06, 0.03, 0.03, 0.03, 0.03, 0.03, 0.2]
train_num = 150000
max_workers = 30
row_num = 86

def get_result_list(dir, csv_filename_list):
    temp_list = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for csv_filename in csv_filename_list:
            temp_list.append(executor.submit(get_result_list_sub, dir, csv_filename))
        executor.shutdown(wait=True)
    filelist = []
    result_list = []
    for i in temp_list:
        file, result = i.result()
        filelist += file
        result_list += result
    zipped = list(zip(result_list, filelist))
    random.shuffle(zipped)
    zipped = sorted(zipped, key=lambda x: x[0])
    result_list, filelist = zip(*zipped)
    c = Counter(result_list)
    counts = [c[i] for i in c]
    result_list = list(result_list)
    filelist = list(filelist)
    amount = [int(train_num*1.1*percentage) for percentage in distribution]
    for i in range(len(classes)-1,-1,-1):
        num = sum(counts[0:i+1])
        if amount[i] < counts[i]:
            del result_list[num-counts[i]+amount[i]+1:num+1]
            del filelist[num-counts[i]+amount[i]+1:num+1]
    result_list.pop(0)
    filelist.pop(0)
    c = Counter(result_list)
    counts = [c[i] for i in c]
    print(counts)
    return result_list, filelist

def get_result_list_sub(dir, csv_filename):
    filelist = []
    result_list = []
    csv_file = list(csv.reader(open(dir + csv_filename + ".csv", encoding='mac_roman'), delimiter=","))
    for row in csv_file:
        if row[0] != "\x1a":
            if row[0] != "Flow ID":
                result = None
                for key, val in classes.items():
                    if row[row_num] in val:
                        result = key
                if result != None:
                    result_list.append(int(result))
                    filelist.append(csv_filename + "-" + row[1] + "-" + row[2] + "-" + row[3] + "-" + row[4])
        else:
            break
    return filelist, result_list

def get_filenames(dir, filename_start_list):
    filenames = {}
    filelists = []
    temp_list = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for filename_start in filename_start_list:
            temp_list.append(executor.submit(get_filenames_sub, dir, filename_start))
        executor.shutdown(wait=True)
    for i in temp_list:
        filelists.append(i.result())
    filenames = {}
    for i in range(len(filename_start_list)):
        filename_start = filename_start_list[i]
        filelist = filelists[i]
        for filename in filelist:
            fileinfotemp = filename.replace(filename_start, "")
            fileinfotemp = fileinfotemp.replace(".pcap", "")
            fileinfotemp = fileinfotemp.replace(".TCP_", "")
            fileinfotemp = fileinfotemp.replace(".UDP_", "")
            fileinfotemp = fileinfotemp.replace("-", ".")
            fileinfotemp = fileinfotemp.replace("_", "-")
            fileinfotemp = filename_start + "-" + fileinfotemp
            filenames[fileinfotemp] = filename_start + "/" + filename
    return filenames

def get_filenames_sub(dir, filename_start):
        try:
            os.system("mono SplitCap.exe -r " + dir + filename_start + ".pcap -s flow -p 8167 -o '" + dir + filename_start + "/'")
            filelist = [file for file in os.listdir(dir + filename_start + "/")]
            return filelist
        except:
            os.system("mv " + dir + filename_start + ".pcap "  + dir + filename_start + "1.pcap")
            os.system("tshark -F pcap -r" + dir + filename_start + "1.pcap -w " + dir + filename_start + ".pcap")
            os.system("rm " + dir + filename_start + "1.pcap")
            os.system("mono SplitCap.exe -r " + dir + filename_start + ".pcap -s flow -p 8167 -o '" + dir + filename_start + "/'")
            filelist = [file for file in os.listdir(dir + filename_start + "/")]
            return filelist

def get_tshark_hexstreams(capture_path: str) -> list:
    cmds = ["tshark", "-x", "-r", capture_path, "-T", "json"]
    frames_text = sp.check_output(cmds, text=True)
    frames_json = json.loads(frames_text)
    hexstreams = [frame["_source"]["layers"]["frame_raw"][0] for frame in frames_json]
    return hexstreams

def get_file_vectors(dir, file):
    hex = get_tshark_hexstreams(dir + file)
    vector = np.array([])
    index = 0
    for packet in hex:
        tempvector = np.array([])
        if index < 10:
            if len(packet) >= 352:
                packet = packet[32: 352]
            else:
                length = 352-len(packet)
                packet = packet + "0"*length
                packet = packet[32: 352]
            for num in range(0, 320, 2):
                tempvector = np.concatenate((tempvector, np.array([[int(packet[num:num+2], 16)/255.]])), axis=None)
            vector = np.concatenate((vector, tempvector), axis=0)
            index += 1
        else:
            break
    while vector.shape != (1600,):
        tempvector = np.array([0]*160)
        vector = np.concatenate((vector, tempvector), axis=0)
    return vector

def get_file_info(dir, filename_list):
    file_labels, file_info = get_result_list(dir, filename_list)
    print("results obtained: " + str(len(file_labels)))
    filenames = get_filenames(dir, filename_list)
    print("filenames obtained: " + str(len(filenames)))
    c = Counter(file_labels)
    print([(i, c[i] / len(file_labels) * 100.0) for i in c])
    index = 0
    filename_list = []
    while index < int(len(file_info)):
        try:
            file_id = file_info[index]
            filename_list.append(filenames[file_id])
            # del filenames[file_id]
            index += 1
        except:
            del file_info[index], file_labels[index]
    del filenames
    del file_info
    c = Counter(file_labels)
    counts = [c[i] for i in c]
    print(counts)
    amount = [int(train_num*percentage) for percentage in distribution]
    for i in range(len(classes)-1,-1,-1):
        num = sum(counts[0:i+1])
        if amount[i] < counts[i]:
            del file_labels[num-counts[i]+amount[i]+1:num+1], filename_list[num-counts[i]+amount[i]+1:num+1]
    file_labels.pop(0)
    filename_list.pop(0)
    zipped = list(zip(file_labels, filename_list))
    random.shuffle(zipped)
    file_labels, filename_list = zip(*zipped)
    c = Counter(file_labels)
    counts = [(i, c[i]) for i in c]
    print(counts)
    temp_list = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for file in filename_list:
            temp_list.append(executor.submit(get_file_vectors, dir, file))
        executor.shutdown(wait=True)
    del filename_list
    print("deleted unnessasary stuff")
    file_vectors = []
    while temp_list!=[]:
        file_vectors.append(temp_list[0].result())
        del temp_list[0]
    del temp_list
    print("list length = " + str(len(file_labels)))
    c = Counter(file_labels)
    print([(i, c[i] / len(file_labels) * 100.0) for i in c])
    split_num = round(len(file_labels) * 0.8) + 1
    test_labels = tf.keras.utils.to_categorical(np.array(file_labels[split_num:]), num_classes = len(classes))
    test_vectors = np.array(file_vectors[split_num:]).astype(np.float32)
    file_labels = tf.keras.utils.to_categorical(np.array(file_labels[0: split_num]), num_classes = len(classes))
    file_vectors = np.array(file_vectors[0:split_num]).astype(np.float32)
    print("splitted the lists")
    return file_labels, file_vectors, test_labels, test_vectors

train_labels, train_vectors, test_labels, test_vectors = get_file_info(directory, filename_list)
with open(directory + output_dir + ".npz", "wb") as file:
    np.savez(file, train_labels=train_labels, train_vectors=train_vectors, test_labels=test_labels, test_vectors=test_vectors)
