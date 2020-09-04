import os
from datetime import datetime
from re import finditer
import hashlib
from multiprocessing import Pool, cpu_count
from functools import partial
import zipfile
import argparse
from argparse import RawTextHelpFormatter

"""
Roadmap:
Multiprocessing to carve the identified plists
Multiprocessing of archives (possibily temp mount?)
Limit size of files to carve from (min and/or max)
Prevent carving initial plist file (possibily only if .plist)
Read plists (bplist and xml) to identify base64 encoded plists
Reduse/eliminate global variable usage
GUI

Questions:
Closing reports vs keeping them open and in ram
"""


def process_search_results():

    global search_results, plist_list, header_list, trailer_list, data, process_item

    # separate header/trailer list returned as grouped lists
    header_list, trailer_list = separate_search_results()

    # match headers and trailers to identify likely plist files
    plist_list = match_headers_and_trailers()

    # carve out identified plist files
    carve_plists()

    # update report for carved plist
    report_plists_carved()


def separate_search_results():  # separate header/trailer list returned as grouped lists

    separate_header_list = []
    separate_trailer_list = []

    global search_results

    for search_hit in search_results:

        if len(search_hit[0]) > 0:

            for header in search_hit[0]:

                separate_header_list.append(header)

        if len(search_hit[1]) > 0:

            for trailer in search_hit[1]:

                separate_trailer_list.append(trailer)

    return separate_header_list, separate_trailer_list


def match_headers_and_trailers():

    global plist_list, header_list, trailer_list

    plist_list = []
    header_list = set(header_list)

    # match headers and trailers
    # if header offset + plist size = end of trailer = plist
    for header in header_list:

        for trailer in trailer_list:

            if header + trailer[0] == trailer[1]:

                new_plist = [header, trailer[0]]

                plist_list.append(new_plist)

    return plist_list


def carve_plists():  # carve identified plist files

    global total_duplicates, plist_list, data, process_item

    for entry in plist_list:

        data.seek(entry[0], 0)

        carved_data = data.read(entry[1])

        md5_hash = hashlib.md5(carved_data).hexdigest()

        carved_filename = md5_hash + ".plist"

        output_item = os.path.join(report_folder, export_folder, carved_filename)

        if not os.path.exists(output_item):

            output_file = open(output_item, "wb")

            output_file.write(carved_data)

            output_file.close()

        else:

            total_duplicates += 1

        hash_entry = "\n%s,%s,%d,%d" % (md5_hash, process_item, entry[0], entry[1])

        hash_file.write(hash_entry)


def report_plists_carved():  # update report for identified plist file

    global plist_list, process_item

    if len(plist_list) > 0:

        global files_containing_plists, total_identified

        files_containing_plists += 1

        total_identified += len(plist_list)

        report_entry = "\n%s\nIdentified plists: %d" % (process_item, len(plist_list))

        report_file.write(report_entry)


def create_chunks_list():  # create a list of chunks to read

    global file_size

    i = 0

    chunk_start_list = []

    while i < file_size:

        chunk_start_list.append(i)

        i += chunk_size - 32  # subtract trailer length in case trailer breaks over chunk

    return chunk_start_list


# regex search of chunks for "bplist" and trailer pattern
# for trailers, calculate plist size
def search_chunks(search_object, size_of_chunks, processing_type, start_location):

    header_pattern = b"\x62\x70\x6C\x69\x73\x74"  # bplist (bplist00 is most common, but there are others)
    trailer_pattern = b"\x00\x00\x00\x00\x00\x00"
    search_pattern = b"(?=((\x62\x70\x6C\x69\x73\x74)|([\x00]{6}[\x01-\x04][\x01-\x04][\x00-\xFF]{24})))"

    header_search_list = []
    trailer_search_list = []

    if processing_type != "zip":

        try:

            data_item = data

        except Exception as e:

            data_item = open(search_object, "rb")

    elif processing_type == "zip":

        data_item = zip_file.open(search_object)

    else:

        data_item = None

    data_item.seek(start_location, 0)

    data_read = data_item.read(size_of_chunks)

    for search in finditer(search_pattern, data_read):

        search_item = search.group(1)

        search_start = search.start(1) + start_location

        if search_item == header_pattern:

            header_search_list.append(search_start)

        elif search_item[:6] == trailer_pattern:

            off_ints_size = int.from_bytes(search_item[6:7], "big")  # offset into size

            # obj_ref_size = int.from_bytes(found[7:8], "big")  # object ref size
            obj_cnt = int.from_bytes(search_item[9:16], "big")  # offsets in table ( number of objects)

            # top_lvl_obj = int.from_bytes(found[17:24], "big")  # element which is top level object
            off_tbl_start = int.from_bytes(search_item[25:32], "big")  # offset table offset

            off_tbl_size = off_ints_size * obj_cnt  # offset table size ##Don't store??

            plist_size = off_tbl_start + off_tbl_size + 32  # offset table size + trailer (32) + table offset

            if plist_size <= search_start + 32:

                plist_end_offset = search_start + 32  # offset for plist end

                new_trailer = [plist_size, plist_end_offset]

                trailer_search_list.append(new_trailer)

    if header_search_list is not None or trailer_search_list is not None:

        return header_search_list, trailer_search_list


def finish_report():  # finalize report

    global input_item

    report_file.write("\n\nProcessed item: " + input_item)

    report_file.write("\n\nStart time: " + start_time_report)

    report_file.write("\nEnd time: " + end_time.strftime(time_format_report))

    report_file.write("\nElapsed time: " + str(end_time - start_time))

    report_file.write("\n\nFiles processed: " + str(files_processed))

    if read_error_count > 0:

        report_file.write("\nFile read errors: " + str(read_error_count))

    if skipped_size_count > 0:

        report_file.write("\nFiles skipped: " + str(skipped_size_count))

    report_file.write("\nFiles containing plists: " + str(files_containing_plists))

    if total_identified > 0:

        report_file.write("\nPlists identified: " + str(total_identified))

    if total_duplicates > 0:

        report_file.write("\nDuplicates identified: " + str(total_duplicates))

    if total_identified > 0:

        report_file.write("\nPlists exported: " + str(total_identified - total_duplicates))


def update_diagnostic_log():  # update diagnostic log with processing information

    diagnostic_file.write("\n%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s"
                          % (input_item, process_type, enable_multiprocessing, use_cores, files_processed,
                             read_error_count, skipped_size_count, files_containing_plists, total_identified,
                             total_duplicates, total_identified - total_duplicates, start_time, end_time,
                             end_time - start_time))


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Binary Plist Carver", formatter_class=RawTextHelpFormatter)

    parser.add_argument("-t", choices=["file", "folder", "zip"], required=True, action="store",
                        help="Input type (required)")

    parser.add_argument("-m", choices=["0", "1", "2", "3"], default=1, action="store",
                        help="Multiprocessing opiton: \n0 = No multiprocessing\n1 = 50 percent core usage (default)"
                             "\n2 = 75 percent core usage\n3 = 100 percent core usage"
                             "\nNOTE: Not currently available for zip files")

    parser.add_argument("-d", help="Enable diagnostic logs", action="store_true", default=False)

    parser.add_argument("-i", help="Input to analyze", required=True, action="store")

    args = parser.parse_args()

    time_format_filename = "%Y%m%d_%H%M%S"
    time_format_report = "%Y-%m-%d_%H:%M:%S"
    version = "vE0.1 (2020) [multiprocessing]"
    start_time = datetime.now()
    start_time_report = start_time.strftime(time_format_report)
    output_folder = "plist_carver_output"
    report_folder = output_folder + "/plist_carver_" + start_time.strftime(time_format_filename)
    export_folder = "carved_files"
    report_filename = "report.txt"
    hash_filename = "hash list.txt"
    diagnostic_filename = "diagnostic logs.txt"
    diagnostic_logging = args.d
    log_filename = "log.txt"
    output_paths = os.path.join(report_folder, export_folder)

    header_list = []
    trailer_list = []
    plist_list = []

    skipped_size_count = 0
    files_containing_plists = 0
    read_error_count = 0
    total_identified = 0
    total_duplicates = 0
    files_processed = 0

    chunk_size = 1000000

    report_file = None
    hash_file = None
    log_file = None

    process_type = args.t

    input_item = args.i

    multiprocessing_option = int(args.m)

    if multiprocessing_option == 0:

        enable_multiprocessing = False

        use_cores = 1

    elif multiprocessing_option == 1:

        enable_multiprocessing = True

        use_cores = int(cpu_count() * 0.5)

    elif multiprocessing_option == 2:

        enable_multiprocessing = True

        use_cores = int(cpu_count() * 0.75)

    elif multiprocessing_option == 3:

        enable_multiprocessing = True

        use_cores = cpu_count()

    if not os.path.exists(output_paths):

        os.makedirs(output_paths)

    report_file_path = os.path.join(report_folder, report_filename)

    if not os.path.exists(report_file_path):

        report_file = open(report_file_path, "w+")

        report_file.write("Plist Carver version %s\n" % version)

    else:

        report_file = open(report_file_path, "a")

        report_file.write("\nPlist Carver version %s (%s)\n" % (version, start_time_report))

    hash_file_path = os.path.join(report_folder, hash_filename)

    if not os.path.exists(hash_file_path):

        hash_file = open(hash_file_path, "w+")

        hash_file.write("MD5 hash list,original file,starting offset,plist size")

    else:

        hash_file = open(hash_file_path, "a")

        hash_file.write("\n\nreport appended %s" % start_time_report)

        hash_file.write("\nMD5 hash list,original file,starting offset,plist size")

    log_file_path = os.path.join(report_folder, log_filename)

    if not os.path.exists(log_file_path):

        log_file = open(log_file_path, "w+")

        log_file.write("Log File (%s),Plist Carver version %s\n"
                       % (start_time_report, version))
    else:

        log_file = open(log_file_path, "a")

        log_file.write("\n\nLog File (%s),Plist Carver version %s\n"
                       % (start_time_report, version))

    diagnostic_path = os.path.join(output_folder, diagnostic_filename)

    if not os.path.exists(diagnostic_path):

        diagnostic_file = open(diagnostic_path, "w+")

        diagnostic_file.write("Diagnostic Logs (%s) Plist Carver version %s" % (start_time_report, version))

        diagnostic_file.write("\ninput_item,process_type,enable_multiprocessing,cores_used,files_processed,"
                              "read_error_count,skipped_files,files_containing_plists,total_plists_identified,"
                              "total_duplicates,exported_plist,start_time,end_time,elapsed_time")

    else:

        diagnostic_file = open(diagnostic_path, "a")

    if process_type == "file":

        process_item = input_item

        file_size = os.path.getsize(process_item)

        chunk_list = create_chunks_list()

        try:

            data = open(process_item, "rb")

            if not enable_multiprocessing:

                search_results = []

                for location in chunk_list:

                    search_results.append(search_chunks(process_item, chunk_size, process_type, location))

            if enable_multiprocessing:

                cores = cpu_count()

                pool = Pool(int(cores / 2))

                func = partial(search_chunks, process_item, chunk_size, process_item)

                search_results = pool.map(func, chunk_list)

                pool.close()

                pool.join()

            process_search_results()

            files_processed += 1

        except Exception as error_item:

            read_error_count += 1

            log_file.write("%s,%s" % (process_item, error_item))

    elif process_type == "folder":

        for root, dirs, files in os.walk(input_item):

            for name in files:

                process_item = os.path.join(root, name)

                file_size = os.path.getsize(process_item)

                chunk_list = create_chunks_list()

                try:

                    data = open(process_item, "rb")

                    if not enable_multiprocessing:

                        search_results = []

                        for location in chunk_list:

                            search_results.append(search_chunks(process_item, chunk_size, process_type, location))

                    if enable_multiprocessing:

                        cores = cpu_count()

                        pool = Pool(int(cores / 2))

                        func = partial(search_chunks, process_item, chunk_size, process_item)

                        search_results = pool.map(func, chunk_list)

                        pool.close()

                        pool.join()

                    process_search_results()

                    files_processed += 1

                except Exception as error_item:

                    read_error_count += 1

                    log_file.write("%s,%s" % (process_item, error_item))

    elif process_type == "zip":

        zip_file = zipfile.ZipFile(input_item)

        for zip_item in zip_file.namelist():

            process_item = zip_item

            file_size = zip_file.getinfo(zip_item).file_size

            chunk_list = create_chunks_list()

            data = zip_file.open(zip_item)

            search_results = []

            for location in chunk_list:

                search_results.append(search_chunks(process_item, chunk_size, process_type, location))

            process_search_results()

            files_processed += 1

    end_time = datetime.now()

    if diagnostic_logging:

        update_diagnostic_log()

    finish_report()
