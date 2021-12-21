def save_DB():
    """
    Use: save the new row to the DB 
    Input: new data
    Output: None
    """
    pass

def requested_domain_in_database(packet, database):
    """
    Use: check if the dns packet request is in the data base or not 
    Input: packet database
    Output: None
    """
    #for record in database:
     #   if packet[DNS]

def parse_DB():
    """
    Use: parse DB rows to a dictionary 
    Input: None
    Output: the dns records 
    """
    dns_records = []
    with open("DB.txt", "r") as file_handle:
        line = file_handle.readline()
        
        while line:

            dns_records.append(line.split(',')) # can cause some issues
            line = file_handle.readline()

    return dns_records

