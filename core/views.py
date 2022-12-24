from virusshare import VirusShare
from django.shortcuts import redirect, render
from django.http.response import  HttpResponse, HttpResponseRedirect
from .models import FilestoScan
import pefile
from django.contrib import messages
import pickle
import math
import hashlib
import array
import time

# Create your views here.


def get_entropy(data):
    '''Information Entropy or Shannon's entropy quantifies the amount of uncertainty (or surprise) involved in the value of a random variable or the outcome of a random process.'''
    try:
        if len(data) == 0:
            return 0.0
        occurences = array.array('L', [0]*256)
        for x in data:
            occurences[x if isinstance(x, int) else ord(x)] += 1
    
        entropy = 0
        for x in occurences:
            if x:
                p_x = float(x) / len(data)
                entropy -= p_x*math.log(p_x, 2)
    
        return entropy
    except:
        return 0.0


def get_resources(pe):
    '''resources are read-only data embedded in portable executable files like EXE, DLL, CPL, SCR, SYS or (beginning with Windows Vista) MUI files'''
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                size = resource_lang.data.struct.Size
                                entropy = get_entropy(data)
                                resources.append([entropy, size])
        except Exception as e:
            return resources
    return resources


def get_version_info(pe):
    res = []
    try:
        for fileinfo in pe.FileInfo:
                for st in fileinfo[0].StringTable:
                    for entry in st.entries.items():
                        res.append(entry[1])
                for var in fileinfo[1].Var:
                    res.append(var)
        if hasattr(pe, 'VS_FIXEDFILEINFO'):
            res.append(pe.VS_FIXEDFILEINFO[0].FileFlags)
            res.append(pe.VS_FIXEDFILEINFO[0].FileOS)
            res.append(pe.VS_FIXEDFILEINFO[0].FileType)
            res.append(pe.VS_FIXEDFILEINFO[0].FileVersionLS)
            res.append( pe.VS_FIXEDFILEINFO[0].ProductVersionLS)
            res.append(pe.VS_FIXEDFILEINFO[0].Signature)
            res.append( pe.VS_FIXEDFILEINFO[0].StrucVersion)
        return res
    except:
        return res


def extract_features(pe):
    feature_list=[]
    try:
        '''The Machine field has one of the following values, which specify the CPU type. An image file can be run only on the specified machine or on a system that emulates the specified machine.'''
        feature_list.append(int(pe.FILE_HEADER.Machine))
    except:
        feature_list.append(0)
    try:
        '''Every image file has an optional header that provides information to the loader.'''
        feature_list.append(int(pe.FILE_HEADER.SizeOfOptionalHeader))
    except:
        feature_list.append(0)
    try:
        '''The Characteristics field contains flags that indicate attributes of the object or image file. The following flags are currently defined:'''
        feature_list.append(int(pe.FILE_HEADER.Characteristics))
    except:
        feature_list.append(0)
    try:
        '''The first eight fields of the optional header are standard fields that are defined for every implementation of COFF. These fields contain general information that is useful for loading and running an executable file.'''
        feature_list.append(int(pe.OPTIONAL_HEADER.MajorLinkerVersion))
    except:
        feature_list.append(0)
    try:
        feature_list.append(int(pe.OPTIONAL_HEADER.MinorLinkerVersion))
    except:
        feature_list.append(0)
    try:
        '''The size of the code (text) section, or the sum of all code sections if there are multiple sections. '''
        feature_list.append(int(pe.OPTIONAL_HEADER.SizeOfCode))
    except:
        feature_list.append(0)
    try:
        '''The size of the initialized data section, or the sum of all such sections if there are multiple data sections. '''
        feature_list.append(int(pe.OPTIONAL_HEADER.SizeOfInitializedData))
    except:
        feature_list.append(0)
    try:
        '''The size of the uninitialized data section (BSS), or the sum of all such sections if there are multiple BSS sections. '''
        feature_list.append(int(pe.OPTIONAL_HEADER.SizeOfUninitializedData))
    except:
        feature_list.append(0)
    try:
        feature_list.append(int(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
    except:
        feature_list.append(0)
    try:
        '''The address that is relative to the image base of the beginning-of-code section when it is loaded into memory. '''
        feature_list.append(int(pe.OPTIONAL_HEADER.BaseOfCode))
    except:
        feature_list.append(0)
    try:
        '''The address that is relative to the image base of the beginning-of-data section when it is loaded into memory. '''
        feature_list.append(int(pe.OPTIONAL_HEADER.BaseOfData))
    except:
        feature_list.append(0)
    try:
        '''The preferred address of the first byte of image when loaded into memory; must be a multiple of 64 K. The default for DLLs is 0x10000000. The default for Windows CE EXEs is 0x00010000. The default for Windows NT, Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is 0x00400000. '''    
        feature_list.append(int(pe.OPTIONAL_HEADER.ImageBase))
    except:
        feature_list.append(0)
    try:
        '''The alignment (in bytes) of sections when they are loaded into memory. It must be greater than or equal to FileAlignment. The default is the page size for the architecture. '''
        feature_list.append(int(pe.OPTIONAL_HEADER.SectionAlignment))
    except:
        feature_list.append(0)
    try:
        '''The alignment factor (in bytes) that is used to align the raw data of sections in the image file. The value should be a power of 2 between 512 and 64 K, inclusive. The default is 512. If the SectionAlignment is less than the architecture's page size, then FileAlignment must match '''
        feature_list.append(int(pe.OPTIONAL_HEADER.FileAlignment))
    except:
        feature_list.append(0)
    try:
        '''The major version number of the required operating system. '''
        feature_list.append(int(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion))
    except:
        feature_list.append(0)
    try:
        '''The minor version number of the required operating system. '''
        feature_list.append(int(pe.OPTIONAL_HEADER.MinorOperatingSystemVersion))
    except:
        feature_list.append(0)
    try:
        '''The major version number of the image. '''
        feature_list.append(int(pe.OPTIONAL_HEADER.MajorImageVersion))
    except:
        feature_list.append(0)
    try:
        '''The minor version number of the image.'''
        feature_list.append(int(pe.OPTIONAL_HEADER.MinorImageVersion))
    except:
        feature_list.append(0)
    try:
        feature_list.append(int(pe.OPTIONAL_HEADER.MajorSubsystemVersion))
    except:
        feature_list.append(0)
    try:
        feature_list.append(int(pe.OPTIONAL_HEADER.MinorSubsystemVersion))
    except:
        feature_list.append(0)
    try:
        '''The size (in bytes) of the image, including all headers, as the image is loaded in memory. It must be a multiple of SectionAlignment.'''
        feature_list.append(int(pe.OPTIONAL_HEADER.SizeOfImage))
    except:
        feature_list.append(0)
    try:
        """The combined size of an MS-DOS stub, PE header, and section headers rounded up to a multiple of FileAlignment. """
        feature_list.append(int(pe.OPTIONAL_HEADER.SizeOfHeaders))
    except:
        feature_list.append(0)
    try:
        '''The image file checksum. The algorithm for computing the checksum is incorporated into IMAGHELP.DLL. The following are checked for validation at load time: all drivers, any DLL loaded at boot time, and any DLL that is loaded into a critical Windows process. '''
        feature_list.append(int(pe.OPTIONAL_HEADER.CheckSum))
    except:
        feature_list.append(0)
    try:
        '''The subsystem that is required to run this image. For more information'''
        feature_list.append(int(pe.OPTIONAL_HEADER.Subsystem))
    except:
        feature_list.append(0)
    try:
        '''Dynamic Link Liberary Characterstcis'''
        feature_list.append(int(pe.OPTIONAL_HEADER.DllCharacteristics))
    except:
        feature_list.append(0)
    try:
        feature_list.append(int(pe.OPTIONAL_HEADER.SizeOfStackReserve))
    except:
        feature_list.append(0)
    try:
        '''The size of the stack to commit. '''
        feature_list.append(int(pe.OPTIONAL_HEADER.SizeOfStackCommit))
    except:
        feature_list.append(0)
    try:
        '''The size of the local heap space to reserve. Only SizeOfHeapCommit is committed; the rest is made available one page at a time until the reserve size is reached. '''
        feature_list.append(int(pe.OPTIONAL_HEADER.SizeOfHeapReserve))
    except:
        feature_list.append(0)
    try:
        '''The size of the local heap space to commit. '''
        feature_list.append(int(pe.OPTIONAL_HEADER.SizeOfHeapCommit))
    except:
        feature_list.append(0)
    try:
        '''Reserved, must be zero. '''
        feature_list.append(int(pe.OPTIONAL_HEADER.LoaderFlags))
    except:
        feature_list.append(0)
    try:
        '''The number of data-directory entries in the remainder of the optional header. Each describes a location and size. '''
        feature_list.append(int(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes))
    except:
        feature_list.append(0)
    try:
        '''The number of entries in the section table is given by the NumberOfSections field in the file header'''
        feature_list.append(int(pe.FILE_HEADER.NumberOfSections))
    except:
        feature_list.append(0)
    sectionEntropies=[]
    sectionRawDataSize=[]
    sectionVirtualSize=[]
    for section in pe.sections:
        try:
            sectionEntropies.append(section.get_entropy())
        except:
            pass
        try:
            sectionRawDataSize.append(section.SizeOfRawData)
        except:
            pass
        try:
            sectionVirtualSize.append(section.Misc_VirtualSize)
        except:
            pass
    try:
        feature_list.append(round(float(sum(sectionEntropies)/len(sectionEntropies)),11))
    except:
        feature_list.append(0)
    try:
        feature_list.append(round(min(sectionEntropies),12))
    except:
        feature_list.append(0)
    try:
        feature_list.append(round(max(sectionEntropies),11))
    except:
        feature_list.append(0)
    try:
        feature_list.append(round(float(sum(sectionRawDataSize)/len(sectionRawDataSize)),11))
    except:
        feature_list.append(0)
    try:
        feature_list.append(round(min(sectionRawDataSize),12))
    except:
        feature_list.append(0)
    try:
        feature_list.append(round(max(sectionRawDataSize),12))
    except:
        feature_list.append(0)
    try:
        feature_list.append(round(float(sum(sectionVirtualSize)/len(sectionVirtualSize)),11))
    except:
        feature_list.append(0)
    try:
        feature_list.append(round(min(sectionVirtualSize),12))
    except:
        feature_list.append(0)
    try:
        feature_list.append(round(max(sectionVirtualSize),12))
    except:
        feature_list.append(0)
    importedDLLs=[]
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            importedDLLs.append(entry.dll.decode('utf-8'))
    except:
        pass
    try:
        feature_list.append(len(importedDLLs))
    except:
        feature_list.append(0)
    numberOfImports=[]
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            for func in entry.imports:
                numberOfImports.append(func)
    except:
        pass
    try:
        feature_list.append(len(numberOfImports))
    except:
        feature_list.append(0)
    callByOrdinal=[]
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.ordinal != None:
                    callByOrdinal.append(imp.ordinal)
    except:
        pass
    
    try:
        feature_list.append(len(callByOrdinal))
    except:
        feature_list.append(0)
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        NumbeOfexports = [(e.ordinal, e.name) for e in pe.DIRECTORY_ENTRY_EXPORT.symbols][0][0]
        feature_list.append(NumbeOfexports)
    except:
        feature_list.append(0)
    numberOfResouces=[]
    try:
        for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            for i in rsrc.directory.entries:
                numberOfResouces.append(i)
    except:
        pass
    try:
        feature_list.append(len(numberOfResouces))
    except:
        feature_list.append(0)

    res={}
    resources= get_resources(pe)
    if len(resources)> 0:
        entropy = list(map(lambda x:x[0], resources))
        res['ResourcesMeanEntropy'] = sum(entropy)/float(len(entropy))
        res['ResourcesMinEntropy'] = min(entropy)
        res['ResourcesMaxEntropy'] = max(entropy)
        sizes = list(map(lambda x:x[1], resources))
        res['ResourcesMeanSize'] = sum(sizes)/float(len(sizes))
        res['ResourcesMinSize'] = min(sizes)
        res['ResourcesMaxSize'] = max(sizes)
    else:
        res['ResourcesMeanEntropy'] = 0
        res['ResourcesMinEntropy'] = 0
        res['ResourcesMaxEntropy'] = 0
        res['ResourcesMeanSize'] = 0
        res['ResourcesMinSize'] = 0
        res['ResourcesMaxSize'] = 0
    for i in res.values():
        feature_list.append(round(i,11))
    try:
        LoadConfigureationsize=pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
        feature_list.append(LoadConfigureationsize)
    except:
        feature_list.append(0)
    try:
        versionInformationSize=len(get_version_info(pe))
        feature_list.append(versionInformationSize)
    except:
        feature_list.append(0)
    return feature_list



def sendMail(name,email,subject,msg):
    f = open('media/pass.txt')
    p= f.readline()
    f.close()
    password = p
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    mail_content = f"Name: {name}\nEmail: {email}\nSubject: {subject}\nMessage: {msg}"
    #The mail addresses and password
    sender_address = 'scannware@gmail.com'
    sender_pass = p
    receiver_address = 'usmansadiq.cs@gmail.com'
    #Setup the MIME
    message = MIMEMultipart()
    message['From'] = sender_address
    message['To'] = receiver_address
    message['Subject'] = 'Mail From ScanWare'   #The subject line
    #The body and the attachments for the mail
    message.attach(MIMEText(mail_content, 'plain'))
    #Create SMTP session for sending the mail
    session = smtplib.SMTP('smtp.gmail.com', 587) #use gmail with port
    session.starttls() #enable security
    session.login(sender_address, sender_pass) #login with mail_id and password
    text = message.as_string()
    session.sendmail(sender_address, receiver_address, text)
    
    session.quit()

def home(request):
    if request.method == 'POST':
        name=request.POST['name']
        email = request.POST['email']
        subject = request.POST['subject']
        message = request.POST['message']
        sendMail(name,email,subject,message)
        messages.info(request, 'Your message has been sent !')
        return HttpResponseRedirect('/')
    else:
        return render(request, 'core/base.html')

def result(request):
    f= open('media/results.txt','r')
    results=[i.strip() for i in f.readlines()]
    fileName=results[0]
    status=results[1]
    return render(request, 'core/result.html',{"fileName":fileName,'Status':status})
def hashing(file):
    # BUF_SIZE is totally arbitrary, change for your app!
    BUF_SIZE = 65536  # lets read stuff in 64kb chunks!
    md5 = hashlib.md5()
    sha1 = hashlib.sha256()
    with open(file, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
            sha1.update(data)
    return md5.hexdigest(),sha1.hexdigest()
def uploadfile(request):
    if request.method == 'POST':
        file = request.FILES['fileupload']
        document = FilestoScan.objects.create(file=file)
        document.save()
        toScan = FilestoScan.objects.all().last()
        clf = pickle.load(open('media/CLF_RandomForest_99.2.sav', 'rb'))
        try:
            features = extract_features(pefile.PE(f"media/{toScan.file}"))
            prediction=clf.predict([features])
            # time.sleep(20)
            v = VirusShare('CvSr65e3p4CARl4ZVAEOKA2pLo5g1cbR')
            h = hashing(f"media/{toScan.file}")[1]
            result = v.info(h)
            if result['data']['response'] == 1:
                prediction = [0]
            else:
                prediction = [1]
        except:
            prediction = [1]
        if prediction == [1]:
            results = 'no'
        else:
            results = 'yes'
        f=open("media/results.txt",'w+')
        f.write(f"{toScan.file}\n{results}")
        f.close()
        FilestoScan.objects.all().delete()
        return redirect('result')
    else:
        return HttpResponse('Not Sucessfull')

def download(request):
    return HttpResponseRedirect('Smart-Detector.rar')

