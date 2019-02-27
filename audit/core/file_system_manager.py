import os
import ntpath


class FileSystemManager:

    def __init__(self):
        pass

    @staticmethod
    def count_dir_files(directory):
        return sum([len(files) for r, d, files in os.walk(directory)])

    @staticmethod
    def path_leaf(path):
        head, tail = ntpath.split(path)
        return tail or ntpath.basename(head)

    @staticmethod
    def base_path(path):
        ntpath.dirname(path)

    @staticmethod
    def get_file_size(file_path):
        ntpath.getsize(file_path)
