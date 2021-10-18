import fw_log

def write_result_to_file(list_content, filename):
    """Write content to file"""
    while True:
        try:
            f = open(filename, "a")
            for key, value in list_content.items():
                f.write(f"{key}; {value}; \n")
            f.close()
            break
        except PermissionError:
            input(f"[ERROR] Merci de fermer le fichier {filename} et appuyer sur Entrée")
    

if __name__ == "__main__":
    # Initiate vars
    out_file = r"C:\Users\jlayrisse\logs_fw\out.csv"
    #fw_log_filename = r"C:\Users\jlayrisse\logs_fw\disk-traffic-forward-2021-09-29_0846.log"  # 
    fw_log_filename = r"C:\Users\jlayrisse\logs_fw\disk-traffic-forward-2021-10-12_1426.log"  # SEWAN
    #fw_log_filename = r"C:\Users\jlayrisse\logs_fw\disk-traffic-lite.log"  # Lite

    # Analyse log
    fw_log = fw_log.fw_log_file(fw_log_filename,1000)

    # Display ignored lines
    if fw_log.ignored_lines != 0:
        print(f"[INFO] File contains : {len(fw_log.log_lines)} line(s) ; {fw_log.matched_lines} line(s) does match REGEXP ; {fw_log.ignored_lines} line(s) does not match !")
        user_input = input("[INFO] Type yes to display ignored lines [no]: ")
        if user_input == "yes":
            for line_id,line in enumerate(fw_log.ignored_lines_content):
                print(f"{line_id}. {line}\n")
            input("[INFO] Press any key to continue")
    else:
        input(f"[INFO] File contains : {len(fw_log.log_lines)} line(s) ; all line(s) does match REGEXP!")

    # Select input and output criterias
    in_criterias = fw_log.select_unicity_criterias("INPUT")
    out_criterias = fw_log.select_unicity_criterias("OUTPUT")

    result = fw_log.get_log_matching(in_criterias,out_criterias)
    pass
