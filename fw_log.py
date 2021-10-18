import re
import os
import operator
from tqdm import tqdm

class fw_log_file:
    """Class defining the content of a firewall log file"""
    matched_lines = 0
    ignored_lines = 0
    log_content = list()
    ignored_lines_content = list()
    # REGEXP for Fortinet firewalls
    fortinet_regexp = r'.*vd="(?P<vdom>\S+)" srcip=(?P<src_ip>\S+) ?(srcport=(?P<src_port>\d+))? '\
        r'.*srcintf="(?P<src_iface>\S+)" .*dstip=(?P<dst_ip>\S+) ?(dstport=(?P<dst_port>\d+))? '\
        r'.*dstintf="(?P<dst_iface>\S+)" .*proto=(?P<protocol>\d+) action="(?P<action>\S+)" '\
        r'policyid=(?P<policy_id>\d+) .*?(policyname="(?P<policy_name>[^"]+))"? '\
        r'.*?(service="(?P<service>\S+)")? .*'
    """
    # TODO : Check why activating sentbyte / rcvdbytes cause some of line not to match
    r'.*?(sentbyte=(?P<sent_bytes>\d+))? .*'
    r'.*?(rcvdbyte=(?P<received_bytes>\d+))? .*?(sentpkt=(?P<sent_packets>\d+))? '\
    r'.*?(rcvdpkt=(?P<received_packets>\d+))?.*'
    """

    # REGEXP for Palo Alto firewall
    pa_regexp = r'.*:\d+,(?P<src_ip>[^,]+),(?P<dst_ip>[^,]+),(?P<src_nat>[^,]+),(?P<dst_nat>[^,]+),'\
        r'(?P<policy_name>[^,]+),,,(?P<service>[^,]+),[^,]+,(?P<src_zone>[^,]+),(?P<dst_zone>[^,]+),'\
        r'(?P<src_iface>[^,]+),(?P<dst_iface>[^,]+),,[^,]+,[^,]+,[^,]+,(?P<src_port>[^,]+),'\
        r'(?P<dst_port>[^,]+),(?P<src_nat_port>[^,]+),(?P<dst_nat_port>[^,]+),[^,]+,(?P<protocol>[^,]+),'\
        r'(?P<action>[^,]+),(?P<total_bytes>[^,]+),(?P<sent_bytes>[^,]+),(?P<received_bytes>[^,]+),'\
        r'(?P<total_packets>[^,]+),[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,'\
        r'(?P<sent_packets>[^,]+),(?P<received_packets>[^,]+).*'


    def __init__(self, log_file, max_line=-1, fw_type="Fortinet") -> None:
        """Parse log file and compare them with regexp to extract valuable data

        Args:
            log_file ([str]): Log file absolute path
            max_line (int, optional): Defines number of line to be analyzed. Defaults to -1.
        """
        # Check if user provide a Regexp, default to Fortinet
        if fw_type == "Fortinet":
            line_regexp = self.fortinet_regexp
        elif fw_type == "Palo Alto":
            line_regexp = self.pa_regexp
        else:
            print("[INFO] Wrong Firewall type name; default to Fortinet")
            line_regexp = self.fortinet_regexp

        # Check if file provided is a valid log file
        if not self._is_file(log_file):
            print("[ERROR] File provided is not a valid filename")
            return None
        self._get_content(log_file)
        
        # Get log file line number
        if max_line == -1 or max_line > len(self.log_lines):
            max_line = len(self.log_lines)

        # Parse line for the log file (with progress bar)
        for line_number in tqdm(range(max_line), desc="Reading log lines :", total=max_line, unit="log"):
            # Parse each line using fw_log_line class and count them
            line_content = self.log_lines[line_number]
            self.log_content.append(self._analyze_line_log(line_content, line_regexp))


    def _is_file(self, filename):
        """Check if log provided as file and write file_valid parent class attribute

        Args:
            filename ([str]): Absolute path of the log file

        Returns:
            [bool]: True if file is a valid file, False instead
        """
        if os.path.isfile(filename):
            return True
        else:
            return False


    def _get_content(self, filename):
        """Extract content of a file to parent var log_file

        Args:
            filename ([str]): Absolute path of the log file
        """
        with open(filename, "r") as log_file:
            self.log_lines = log_file.readlines()


    def _analyze_line_log(self, log_line, regexp):
        """Analyze the content of each line of log using class fw_log_line

        Args:
            log_line (str): RAW format of firewall log message
            regexp (str): Regular expression to compare log with

        Returns:
            [dict]: dictionary containing line valuable data ordered in dict
        """
        line_content = fw_log_line(log_line, regexp).line_content
        if not line_content:  # Line content is None (no match on Regexp)
            self.ignored_lines += 1  # Increment ignored
            self.ignored_lines_content.append(log_line)
        else:  # There is a match between Regexp and Line
            self.matched_lines += 1 # Increment total line
            return line_content


    def _order_unicity_dict(self, unicity_dict, unicity_in_keys, unicity_out_keys):
        # 1 - Create final list
        unicity_list = list()
        for in_key in unicity_dict:
            out_dict = unicity_dict.get(in_key,False)
            for out_key in out_dict:
                out_value = out_dict.get(out_key, False)
                out_values = (in_key, out_key, out_value)
                unicity_list.append(out_values)

        # Sort dictionary by value
        unicity_list = sorted(unicity_list, key=operator.itemgetter(2), reverse=True)
        unicity_list.insert(0,(unicity_in_keys,unicity_out_keys,("hit_count",)))

        # Unpack dict
        unicity_list_out = list()
        for item in unicity_list:
            unicity_src = list(item[0])
            unicity_dst = list(item[1])
            if isinstance(item[2],tuple):
                unicity_hit = list(item[2])
                unicity_out = unicity_src + unicity_dst + unicity_hit
            else:
                unicity_out = unicity_src + unicity_dst
                unicity_out.append(str(item[2]))
            unicity_list_out.append(unicity_out)

        return unicity_list_out


    def cls(self):
        """Clear everything that appears on screen (Windows + Linux)
        """
        os.system('cls' if os.name=='nt' else 'clear')


    def select_unicity_criterias(self, unicity_type=""):
        """Display a menu to help user to select criterias of unicity

        Args:
            type (str, optional): Define if selection of input or output criteria. Defaults to "input".

        Returns:
            [tuple]: Tuple containing unicity criterias as text
        """
        log_keys = list()
        user_choice_list = list()
        user_choice_list_result = list()

        if len(self.log_content) > 0 and self.log_content[0]:
            # Get key list in var
            for key_value in self.log_content[0].keys():
                log_keys.append(key_value)

            # Prompt user to check his choice
            while True:
                self.cls()  # Clear display
                print(f"Please select keys number from the following list for {unicity_type} criterias:")
                print(f"[INFO] Current selection => {user_choice_list_result}")
                for key_id, key_value in enumerate(log_keys):
                    print(f"{key_id}. {key_value}")
                print("q. quit")
                user_choice = input("type your choice (id only): ")
                try:
                    if (int(user_choice) < len(log_keys)) and (int(user_choice) >= 0):
                        if int(user_choice) not in user_choice_list:
                            user_choice_list.append(int(user_choice))
                            user_choice_list_result.append(log_keys[int(user_choice)])
                    else:
                        input('[ERROR] Value entered is invalid, please try again')
                except ValueError:
                    if (len(user_choice_list_result) > 0 and user_choice == ""):
                        break
                    elif (len(user_choice_list_result) == 0 and user_choice == "" and unicity_type.lower() == "output"):
                        break
                    else:
                        input('[ERROR] Value entered is invalid, please try again')
            user_choice_list_result = tuple(user_choice_list_result)

        return user_choice_list_result


    def get_log_matching(self, unicity_in_keys, unicity_out_keys=("hit_count",)):
        # 0 - Parse all log line (dict)
        unicity_dict = dict()  # This dict will contains unique matching values
        for log_line_dict in self.log_content:
            # Initiate var
            unique_in_list = list()
            unique_out_list = list()
            unique_out_dict_with_hit = dict()
            
            # Do not consider line that does not match any regexp
            if not log_line_dict:
                continue

            # unicity_in_keys
            for unique_key in unicity_in_keys: # Check each unicity key
                unique_in_list.append(log_line_dict.get(unique_key,None))
            unique_in_list = tuple(unique_in_list)

            # unicity_out_keys
            for unique_key in unicity_out_keys: # Check each unicity key
                if unique_key != "hit_count":
                    unique_out_list.append(log_line_dict.get(unique_key,None))
            unique_out_list = tuple(unique_out_list)

            # Check if input key exist result dict
            if not unicity_dict.get(unique_in_list,False): # First match of input key
                unicity_dict[unique_in_list] = dict()
                
            # Check if output key exist
            if not unicity_dict[unique_in_list].get(unique_out_list,False):
                unicity_dict[unique_in_list][unique_out_list] = 1
            else:
                unicity_dict[unique_in_list][unique_out_list] += 1

        unicity_list = self._order_unicity_dict(unicity_dict, unicity_in_keys, unicity_out_keys)

        return unicity_list

         
class fw_log_line:
    """Class defining a the content of a line of a firewall log file"""

    def __init__(self, log_line, line_regexp) -> None:
        """Instantiate a new regexp line"""
        self.regexp = line_regexp
        self._regexp_on_line(log_line)

    def _regexp_on_line(self, log_line):
        """Apply a regexp on a line"""
        re_compile = re.compile(self.regexp)
        re_result = re_compile.match(log_line)
        if re_result:
            self.line_content = re_result.groupdict()
        else:
            self.line_content = None