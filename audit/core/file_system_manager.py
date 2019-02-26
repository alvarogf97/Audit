import os


class FileSystemManager:

    def __init__(self):
        pass

    @staticmethod
    def count_dir_files(directory):
        return sum([len(files) for r, d, files in os.walk(directory)])
