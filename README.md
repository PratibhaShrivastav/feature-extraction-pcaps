# feature-extraction-pcaps
The project provides an automated flow of extracting tar.gz files and extracting network features from the obtained pcap files into csv files.


#### Steps to clone and run the project locally 
1. In terminal, execute the following commands :

    `git clone https://github.com/PratibhaShrivastav/feature-extraction-pcaps.git`

    `cd feature-extraction-pcaps`

2. Upload files in respective folders. Malware data files go in `Pcaps_Malware` folder and benign data files go in `Pcaps_Legitimate` folder. 

3. Make the result folders `CSV_Malware` and `CSV_Legitimate` empty.

4. Run :

    `python main.py`

