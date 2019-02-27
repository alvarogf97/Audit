import os
import ntpath
import shutil


class FileSystemManager:

    def __init__(self):
        pass

    @staticmethod
    def onerror(func, path, exc_info):
        import stat
        if not os.access(path, os.W_OK):
            os.chmod(path, stat.S_IWUSR)
            func(path)
        else:
            raise IOError

    @staticmethod
    def delete_folder(directory):
        shutil.rmtree(directory, onerror=FileSystemManager.onerror)

    @staticmethod
    def count_dir_files(directory):
        return sum([len(files) for r, d, files in os.walk(directory)])

    @staticmethod
    def path_leaf(path):
        head, tail = ntpath.split(path)
        return tail or ntpath.basename(head)

    @staticmethod
    def base_path(path):
        return ntpath.dirname(path)

    @staticmethod
    def get_file_size(file_path):
        return ntpath.getsize(file_path)
