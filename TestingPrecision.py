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

directory = "/home/fyp/Desktop/cnn/"
filename_list = [i.replace(".pcap", "").replace(directory, "") for i in glob.glob(directory + '*.pcap')]
model = tf.keras.models.load_model("/home/kali/Downloads/models/model5/")
classes = {0:["BENIGN"], 1:["FTP-Patator"], 2:["SSH-Patator"], 3:["DoS GoldenEye"], 4:["DoS Hulk"], 5:["DoS Slowhttptest"], 6:["DoS slowloris"], 7:["Web Attack ñ Brute Force", "Web Attack ñ Sql Injection", "Web Attack ñ XSS"], 8:["Bot"], 9:["DDoS"], 10:["PortScan"]}
train_num = 2000
max_workers = 100

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
    result_list, filelist = zip(*zipped)
    no_of_required_files = int(train_num * 8)
    result_list = list(result_list)[0:no_of_required_files]
    filelist = list(filelist)[0:no_of_required_files]
    # result_list = list(result_list)
    # filelist = list(filelist)
    num = int(len(result_list)/3)
    i = 0
    while len(result_list) > num:
        if result_list[i] == 0:
            result_list.pop(i)
            filelist.pop(i)
        else:
            i += 1
    zipped = list(zip(result_list, filelist))
    random.shuffle(zipped)
    result_list, filelist = zip(*zipped)
    result_list = list(result_list)
    filelist = list(filelist)
    return result_list, filelist

def get_result_list_sub(dir, csv_filename):
    filelist = []
    result_list = []
    csv_file = list(csv.reader(open(dir + csv_filename + ".csv", encoding='mac_roman'), delimiter=","))
    for row in csv_file:
        if row[0] != "\x1a":
            if row[0] != "Flow ID":
                result = None
                row_num = 84
                for key, val in classes.items():
                    if row[row_num] in val:
                        result = key
                if result != None:
                    result_list.append(int(result))
                    filelist.append(csv_filename + "-" + row[1] + "-" + row[2] + "-" + row[3] + "-" + row[4])
        else:
            break
    return filelist, result_list

def get_filenames(dir, filename_start_list, files):
    filenames = {}
    filelists = []
    temp_list = []
    temp_list1 = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for filename_start in filename_start_list:
            temp_list.append(executor.submit(get_filenames_sub, dir, filename_start))
        executor.shutdown(wait=True)
    for i in temp_list:
        filelists.append(i.result())
    for i in range(len(filename_start_list)):
        filename_start = filename_start_list[i]
        filelist = filelists[i]
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            num = len(filelist)
            for i in range(0, num+1, 400):
                if num > i:
                    temp_list1.append(executor.submit(get_filenames_sub1, filelist[i: i+400], filename_start, files))
                else:
                    temp_list1.append(executor.submit(get_filenames_sub1, filelist[i: num], filename_start, files))
            executor.shutdown(wait=True)
    for i in temp_list1:
        filenames = {**filenames, **i.result()}
    return filenames

def get_filenames_sub(dir, filename_start):
        try:
            # os.system("mono SplitCap.exe -r " + dir + filename_start + ".pcap -s flow -p 8167 -o '" + dir + filename_start + "/'")
            filelist = [file for file in os.listdir(dir + filename_start + "/")]
            return filelist
        except:
            os.system("mv " + dir + filename_start + ".pcap "  + dir + filename_start + "1.pcap")
            os.system("tshark -F pcap -r" + dir + filename_start + "1.pcap -w " + dir + filename_start + ".pcap")
            os.system("rm " + dir + filename_start + "1.pcap")
            os.system("mono SplitCap.exe -r " + dir + filename_start + ".pcap -s flow -p 8167 -o '" + dir + filename_start + "/'")
            filelist = [file for file in os.listdir(dir + filename_start + "/")]
            return filelist

def get_filenames_sub1(filelist, filename_start, files):
    filenames = {}
    for filename in filelist:
        fileinfotemp = filename.replace(filename_start, "")
        fileinfotemp = fileinfotemp.replace(".pcap", "")
        fileinfotemp = fileinfotemp.replace(".TCP_", "")
        fileinfotemp = fileinfotemp.replace(".UDP_", "")
        fileinfotemp = fileinfotemp.replace("-", ".")
        fileinfotemp = fileinfotemp.replace("_", "-")
        fileinfotemp = filename_start + "-" + fileinfotemp
        if fileinfotemp in files:
            filenames[fileinfotemp] = filename_start + "/" + filename
    return filenames

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
    filenames = get_filenames(dir, filename_list, file_info)
    print("filenames obtained: " + str(len(filenames)))
    file_vectors = []
    temp_list = []
    index = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        while index < len(file_info):
            try:
                temp_list.append(executor.submit(get_file_vectors, dir, filenames[file_info[index]]))
                index += 1
            except:
                file_info.pop(index)
                file_labels.pop(index)
    for i in temp_list:
        file_vectors.append(i.result())
    print("preped the lists")
    file_labels = np.array(file_labels)
    file_vectors = np.array(file_vectors).astype(np.float32)
    return file_labels, file_vectors

file_labels, file_vectors = get_file_info(directory, filename_list)
prediction = np.argmax(model.predict(file_vectors), axis = 1)
total = 0
correct = 0
file_labels = list(file_labels)
prediction = list(prediction)
c = Counter(prediction)
print([(i, c[i] / len(prediction) * 100.0) for i in c])
for index in range(len(file_labels)):
    if prediction[index] != 0:
        total += 1
        if file_labels[index] != 0:
            correct += 1
print("Precision: " + str(correct/total*100) + "%")
