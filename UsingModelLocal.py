import os
import json
import subprocess as sp
import numpy as np
import tensorflow as tf
import csv
import glob
import concurrent.futures

directory = "/home/fyp/Desktop/cnn/pcaps/"
filename_list = [i.replace(".pcap", "").replace(directory, "") for i in glob.glob(directory + '*.pcap')]
model = tf.keras.models.load_model("/home/fyp/Desktop/cnn/Models/model5")
classes = {0: "BENIGN", 1:"FTP-Patator", 2:"SSH-Patator", 3:"DoS GoldenEye", 4:"DoS Hulk", 5:"DoS Slowhttptest", 6:"DoS slowloris", 7:"Web Attack", 8:"Bot", 9:"DDoS", 10:"PortScan"}
max_workers = 20

def get_filenames(dir, filename_start_list):
    temp_list = []
    final_filenames = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for filename_start in filename_start_list:
            temp_list.append(executor.submit(get_filenames_sub, dir, filename_start))
    for i in temp_list:
        final_filenames += i.result()
    return final_filenames

def get_filenames_sub(dir, filename_start):
    filelist = None
    filenames_sub = []
    try:
        os.system("mono SplitCap.exe -r " + dir + filename_start + ".pcap -s flow -p 8167 -o '" + dir + filename_start + "/'")
        filelist = [file for file in os.listdir(dir + filename_start + "/")]
    except:
        os.system("mv " + dir + filename_start + ".pcap "  + dir + filename_start + "1.pcap")
        os.system("tshark -F pcap -r" + dir + filename_start + "1.pcap -w " + dir + filename_start + ".pcap")
        os.system("rm " + dir + filename_start + "1.pcap")
        os.system("mono SplitCap.exe -r " + dir + filename_start + ".pcap -s flow -p 8167 -o '" + dir + filename_start + "/'")
        filelist = [file for file in os.listdir(dir + filename_start + "/")]
    for filename in filelist:
        if ".TCP_" in filename or ".UDP_" in filename:
            if "fe80" not in filename:
                filenames_sub.append(filename_start + "/" + filename)
    return filenames_sub

def get_tshark_hexstreams(capture_path: str) -> list:
    cmds = ["tshark", "-x", "-r", capture_path, "-T", "json"]
    frames_text = sp.check_output(cmds, text=True)
    frames_json = json.loads(frames_text)
    hexstreams = [frame["_source"]["layers"]["frame_raw"][0] for frame in frames_json]
    return hexstreams
    
def get_file_vectors(dir, file):
    hex = get_tshark_hexstreams(dir + "/" + file)
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

def get_labels(vectors):
    nums = np.argmax(model.predict(vectors), axis = 1)
    results = []
    for num in nums:
        for key, val in classes.items():
            if num == key:
                results.append(val)
    return results

def get_file_info(dir, filename_list):
    file_info = get_filenames(dir, filename_list)
    print("filenames obtained: " + str(len(file_info)))
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for info in file_info:
            results.append(executor.submit(get_file_vectors, dir, info))
    vectors = []
    for i in results:
        vectors.append(i.result())
    file_labels = get_labels(np.array(vectors).astype(np.float32))
    return file_info, file_labels

def output(dir, files, labels):
    with open(dir + "/results.csv", "w", encoding='UTF8') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["File", "Label"])
        for index in range(len(files)):
            writer.writerow([files[index], labels[index]])

print(filename_list)
files, labels = get_file_info(directory, filename_list)
output(directory, files, labels)
