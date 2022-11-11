import pandas as pd
from Methods.process_data import ProcessData
import pickle

FILES_PATH = '../Data/CIC-IDS2017/'
FILE_NAME_LIST = [
    [
        'Monday-WorkingHours.pcap_ISCX.csv'
    ],
    [
        'Tuesday-WorkingHours.pcap_ISCX.csv'
    ],
    [
        'Wednesday-workingHours.pcap_ISCX.csv'
    ],
    [
        'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
        'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv'
    ],
    [
        'Friday-WorkingHours-Morning.pcap_ISCX.csv',
        'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
        'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
    ]
]

PROCESSED_FILES_PATH = '../Data/Processed-CIC-IDS2017/'
IP_TIME_MAP_FILE_NAME = 'ip_map_by_day.pkl'

TIME_FILTRATION_COL = [
    ' Source IP',
    ' Timestamp'
]


class TimeModel:
    def generate_ip_time_map():
        ip_map_by_day = {
            0: {},
            1: {},
            2: {},
            3: {},
            4: {}
        }

        for i in range(5):
            file_df = ProcessData.get_file_by_day(i)
            file_df = ProcessData.get_time_data(file_df)
            unique_ip_list = file_df[TIME_FILTRATION_COL[0]].unique()

            for j in unique_ip_list:
                ip_map_by_day[i][j] = set(file_df.loc[file_df[TIME_FILTRATION_COL[0]] == j, TIME_FILTRATION_COL[1]])

        return ip_map_by_day

    def save_ip_time_map(file_path: str, ip_time_map: dict):
        with open(file_path, 'wb') as f:
            pickle.dump(ip_time_map, f)
            print(f"Successfully saved at: {file_path}")

    def read_ip_time_map(file_path: str):
        with open(file_path, 'rb') as f:
            ip_time_map = pickle.load(f)
        return ip_time_map

    def get_euclidean_cluster(time_stamps: set, threshold: int = 15):
        temp_ts_lst = list(time_stamps)
        temp_ts_lst.sort()
        l = len(temp_ts_lst)
        temp_ip_cluster = {0: [temp_ts_lst[0]]}

        cluster_count = 0

        cluster_upper_limit = temp_ts_lst[0]
        for index in range(1, l):
            if cluster_upper_limit + threshold >= temp_ts_lst[index]:
                temp_ip_cluster[cluster_count].append(temp_ts_lst[index])
                cluster_upper_limit = temp_ts_lst[index]
            else:
                cluster_count += 1
                temp_ip_cluster[cluster_count] = [temp_ts_lst[index]]
                cluster_upper_limit = temp_ts_lst[index]

        return temp_ip_cluster

    def generate_time_cluster(ip_map_by_day: dict, cluster_threshold: int):
        for day in ip_map_by_day.keys():
            for ip in ip_map_by_day[day].keys():
                ip_map_by_day[day][ip] = TimeModel.get_euclidean_cluster(ip_map_by_day[day][ip], cluster_threshold)
        return ip_map_by_day


if __name__ == '__main__':
    # file_df = ProcessData.get_file_by_day(4)
    # print(file_df.shape)
    # file_df = ProcessData.get_time_data(file_df)
    # print(file_df.shape)

    # ip_map_by_day = TimeModel.generate_ip_time_map()
    # TimeModel.save_ip_time_map(PROCESSED_FILES_PATH + IP_TIME_MAP_FILE_NAME, ip_map_by_day)

    # ip_map_by_day = TimeModel.read_ip_time_map(PROCESSED_FILES_PATH + IP_TIME_MAP_FILE_NAME)
    # ip_map_by_day = TimeModel.generate_time_cluster(ip_map_by_day, 15)
    # TimeModel.save_ip_time_map(PROCESSED_FILES_PATH + IP_TIME_MAP_FILE_NAME, ip_map_by_day)

    ip_map_by_day = TimeModel.read_ip_time_map(PROCESSED_FILES_PATH + IP_TIME_MAP_FILE_NAME)
    print(ip_map_by_day)
