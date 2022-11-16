import pandas as pd
import pickle

from Methods.process_data import ProcessData
from Methods.process_data import DATA_TYPE

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

"""
ip_map_by_day Data Structure

ip_map_by_day(dict) {
    day(int) : {
        ip(str) : {
            cluster_id(int) : [
                timestamp1,
                timestamp2,
                ...
            ](list-sortedASC)
        }
    }
}
"""

DAY_SCORE_THRESHOLD = [0.2]*5

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

    def is_time_in_cluster(time_cluster: dict, time: int):
        for cluster_id in time_cluster.keys():
            if time_cluster[cluster_id][0] <= time <= time_cluster[cluster_id][-1]:
                return True
        return False

    def get_rounded_time(time: int):
        if time<0:
            return 1440+time
        elif time>1440:
            return time%1440
        else:
            return time

    def get_nearest_times(lower_limit: int, upper_limit: int, time: int):
        if (time-lower_limit) < (upper_limit-time):
            nearest_time = lower_limit
            second_nearest_time = upper_limit
        else:
            nearest_time = upper_limit
            second_nearest_time = lower_limit
        return nearest_time, second_nearest_time

    def get_nearest_clusters_time(time_cluster: dict, time: int):
        cluster_id = 0
        lower_limit = 0  # (time_cluster[0][0] - 720)
        upper_limit = time_cluster[0][0]
        if lower_limit < time < upper_limit:
            nearest_time, second_nearest_time = upper_limit, lower_limit  # TimeModel.get_nearest_times(lower_limit, upper_limit, time)
            return TimeModel.get_rounded_time(nearest_time), TimeModel.get_rounded_time(second_nearest_time)

        for cluster_id in list(time_cluster.keys())[1:]:
            lower_limit = time_cluster[cluster_id - 1][-1]
            upper_limit = time_cluster[cluster_id][0]
            if lower_limit < time < upper_limit:
                nearest_time, second_nearest_time = TimeModel.get_nearest_times(lower_limit, upper_limit, time)
                return TimeModel.get_rounded_time(nearest_time), TimeModel.get_rounded_time(second_nearest_time)

        lower_limit = time_cluster[cluster_id][-1]
        upper_limit = 1440  # (lower_limit + 720)
        if lower_limit < time < upper_limit:
            nearest_time, second_nearest_time = lower_limit, upper_limit  # TimeModel.get_nearest_times(lower_limit, upper_limit, time)
            return TimeModel.get_rounded_time(nearest_time), TimeModel.get_rounded_time(second_nearest_time)

    def generate_score(nearest_dist: int, second_nearest_dist: int):
        if second_nearest_dist > nearest_dist:
            distance_factor = nearest_dist / second_nearest_dist
        else:
            distance_factor = nearest_dist / 720
        sum = (nearest_dist+second_nearest_dist)
        if sum <= 720:
            global_distance_factor = (nearest_dist+second_nearest_dist)/720
        else:
            global_distance_factor = 1
        score = distance_factor * global_distance_factor * 10
        return score

    def get_day_ip_score_by_time(ip_map: dict, ip: str, time: int):
        if ip in ip_map.keys():
            if TimeModel.is_time_in_cluster(ip_map[ip], time):
                return 0
            else:
                nearest_cluster_time, second_nearest_cluster_time = TimeModel.get_nearest_clusters_time(ip_map[ip], time)
                # print(nearest_cluster_time, " - ", second_nearest_cluster_time)
                nearest_distance = abs(time-nearest_cluster_time)
                nearest_distance = nearest_distance if abs(time-nearest_cluster_time) < 720 else (
                        1440-nearest_distance)
                second_nearest_distance = abs(time-second_nearest_cluster_time)
                second_nearest_distance = second_nearest_distance if abs(time - second_nearest_cluster_time) < 720 else (
                        1440 - second_nearest_distance)
                # print(nearest_distance, " - ", second_nearest_distance, "\n")
                ###
                # Any score measuring policy can be added here!
                ###
                return TimeModel.generate_score(nearest_distance,second_nearest_distance)

        else:
            return 10

    def get_overall_ip_score_by_time(ip_map_by_day: dict, ip: str, time: int):
        temp_scores = []
        for day in ip_map_by_day.keys():
            temp_scores.append(TimeModel.get_day_ip_score_by_time(ip_map_by_day[day], ip, time))
        # print(temp_scores)
        temp_scores = [a * b for a, b in zip(DAY_SCORE_THRESHOLD, temp_scores)]
        # print(temp_scores)
        return sum(temp_scores)
    def test_avg_malicious_data_score():
        ip_map_by_day = TimeModel.read_ip_time_map(PROCESSED_FILES_PATH + IP_TIME_MAP_FILE_NAME)
        score = 0
        count = 0
        for i in range(5):
            file_df = ProcessData.get_file_by_day(i, DATA_TYPE.MALICIOUS)
            file_df = ProcessData.get_time_data(file_df)

            for ip, time in zip(file_df[TIME_FILTRATION_COL[0]], file_df[TIME_FILTRATION_COL[1]]):
                score += TimeModel.get_overall_ip_score_by_time(ip_map_by_day, ip, time)
                # print(ip, " - ", time, " - ", score)
            count += file_df.shape[0]

        print("Overall score: ", score/count)


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

    TimeModel.test_avg_malicious_data_score()


    ### TEST DATA
    # '37.59.195.0' - 645
    # '213.19.162.80' - 297
    # '64.71.142.124' - 298

    # test_ip = '172.16.0.1'
    # test_time = 1290
    #
    # ip_map_by_day = TimeModel.read_ip_time_map(PROCESSED_FILES_PATH + IP_TIME_MAP_FILE_NAME)
    # # print(ip_map_by_day)
    # score = TimeModel.get_overall_ip_score_by_time(ip_map_by_day, test_ip, test_time)
    # print(score)
    # for i in range(5):
    #     try:
    #         print(f"Day: {i+1} :: ", ip_map_by_day[i][test_ip])
    #     except:
    #         pass


