import csv, glob, os, json
import pandas as pd
import tarfile

def compute_features():

    def extract_tar():
        inputs = ["Pcaps_Malware", "Pcaps_Legitimate"]
        for input in inputs:
            for path, directories, files in os.walk(input):
                index = 0
                for f in files:
                    if f.endswith(".tar.gz"):
                        index = index + 1
                        tar = tarfile.open(os.path.join(path,f), 'r:gz')
                        tar.extractall(path=path+"/tarfile"+str(index))
                        tar.close()
                        for nestedpath, directories, nestedfiles in os.walk(os.path.join(path,"tarfile"+str(index))):
                            index2 = 0
                            for ff in nestedfiles:
                                if ff.endswith(".tar.gz"):
                                    index2 = index2 + 1
                                    tar = tarfile.open(os.path.join(nestedpath,ff), 'r:gz')
                                    tar.extractall(path=nestedpath+"/tarfile"+str(index2))
                                    tar.close()

    def malware_features():
        cnt = 1
        folder_name = "Pcaps_Malware"
        for pcap in glob.glob(folder_name + '/**/*.pcap', recursive=True):
            os.system("tshark -r {} -T json > file_json".format(pcap))
            f = open('file_json',encoding="utf8") 
            data = json.load(f) 
            data = pd.json_normalize(data)
            file_subname = pcap.split("\\")
            file_name = file_subname[1] + str(cnt) + ".csv"
            cnt = cnt + 1
            data.to_csv(os.path.join("CSV_Malware", file_name))


    def legitimate_features():
        cnt = 1
        folder_name = "Pcaps_Legitimate"
        for pcap in glob.glob(folder_name + '/**/*.pcap', recursive=True):
            os.system("tshark -r {} -T json > file_json".format(pcap))
            f = open('file_json',encoding="utf8") 
            data = json.load(f) 
            data = pd.json_normalize(data)
            file_subname = pcap.split("\\")
            file_name = file_subname[1] + str(cnt) + ".csv"
            cnt = cnt + 1
            data.to_csv(os.path.join("CSV_legitimate", file_name))

    extract_tar()
    malware_features()
    legitimate_features()

if __name__== "__main__":
    compute_features()