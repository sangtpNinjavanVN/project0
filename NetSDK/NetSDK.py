from .SDK_Struct import *
from .SDK_Enum import *
from .SDK_Callback import *

sys_platform, python_bit_num = system_get_platform_info()
system_type = sys_platform + python_bit_num
# netsdkdllpath_dict = {
#     "windows64": "..\..\Libs\Win64\dhnetsdk.dll",
#     "windows32": "..\..\Libs\Win32\dhnetsdk.dll",
# }
# configdllpath_dict = {
#     "windows64": "..\..\Libs\Win64\dhconfigsdk.dll",
#     "windows32": "..\..\Libs\Win32\dhconfigsdk.dll",
# }
netsdkdllpath_dict = {
    "windows64": ".\libs\Win64\dhnetsdk.dll",
    "windows32": ".\libs\Win32\dhnetsdk.dll",
}
configdllpath_dict = {
    "windows64": ".\libs\Win64\dhconfigsdk.dll",
    "windows32": ".\libs\Win32\dhconfigsdk.dll",
}
netsdkdllpath = netsdkdllpath_dict[system_type]
configdllpath = configdllpath_dict[system_type]


error_code = {
    0: "No errors",
    -1: "Unknown error",
    1: "System error",
    2: "Network error, maybe because of network timeout",
    3: "Device protocol mismatch",
    4: "The handle is invalid",
    5: "Failed to open channel",
    6: "Failed to close the channel",
    7: "User parameter is invalid",
    8: "SDK initialization error",
    9: "SDK cleanup error",
    10: "Error requesting render resource",
    11: "Error opening decoding library",
    12: "Error closing decoding library",
    13: "The number of channels detected in the multi-screen preview is 0",
    14: "The recording library failed to initialize",
    15: "The recording library is not initialized",
    16: "Error sending audio data",
    17: "The real-time data has been saved",
    18: "No real-time data saved",
    19: "Error opening file",
    20: "Failed to start PTZ control timer",
    21: "Error checking the returned data",
    22: "Not enough cache",
    23: "The current SDK does not support this function",
    24: "Could not find the video",
    25: "No operation permission",
    26: "Unable to execute temporarily",
    27: "Intercom channel not found",
    28: "No audio found",
    29: "Network SDK is not initialized",
    30: "The download has ended",
    31: "The query result is empty",
    32: "Failed to get system property configuration",
    33: "Failed to get serial number",
    34: "Failed to get general properties",
    35: "Failed to obtain DSP capability description",
    36: "Failed to get network configuration",
    37: "Failed to get channel name",
    38: "Failed to get video properties",
    39: "Failed to get video configuration",
    40: "Failed to get decoder protocol name",
    41: "Failed to get 232 serial port function name",
    42: "Failed to get decoder properties",
    43: "Failed to get 232 serial port configuration",
    44: "Failed to get external alarm input configuration",
    45: "Failed to get dynamic detection alarm",
    46: "Failed to get device time",
    47: "Failed to get preview parameters",
    48: "Failed to get automatic maintenance configuration",
    49: "Failed to get video matrix configuration",
    50: "Failed to obtain area occlusion configuration",
    51: "Failed to get image watermark configuration",
    52: "Failed to get configuration location: multicast port is configured by channel",
    55: "Failed to modify general properties",
    56: "Failed to modify network configuration",
    57: "Failed to modify channel name",
    58: "Failed to modify video properties",
    59: "Failed to modify the video configuration",
    60: "Failed to modify decoder properties",
    61: "Failed to modify 232 serial port configuration",
    62: "Failed to modify external input alarm configuration",
    63: "Failed to modify dynamic detection alarm configuration",
    64: "Failed to modify device time",
    65: "Failed to modify preview parameters",
    66: "Failed to modify the automatic maintenance configuration",
    67: "Failed to modify the video matrix configuration",
    68: "Failed to modify the area occlusion configuration",
    69: "Failed to modify image watermark configuration",
    70: "Failed to modify wireless network information",
    71: "Failed to select wireless network device",
    72: "Failed to modify active registration parameter configuration",
    73: "Failed to modify camera property configuration",
    74: "Failed to modify infrared alarm configuration",
    75: "Failed to modify audio alarm configuration",
    76: "Failed to modify storage location configuration",
    77: "The audio encoding interface did not initialize successfully",
    78: "Data too long",
    79: "The device does not support this operation",
    80: "Insufficient device resources",
    81: "The server has started",
    82: "The server has not started successfully",
    83: "The serial number entered is incorrect",
    84: "Failed to get hard disk information",
    85: "Get connection session information",
    86: "The number of times the wrong password is entered exceeds the limit",
    100: "Incorrect password",
    101: "Account does not exist",
    102: "Waiting for login to return timed out",
    103: "The account is logged in",
    104: "Account has been locked",
    105: "The account has been blacklisted",
    106: "Insufficient resources, the system is busy",
    107: "Login to the device timed out, please check the network and try again",
    108: "Network connection failed",
    109: "Login to the device is successful, but the video channel cannot be created, please check the network status",
    110: "Exceeded maximum number of connections",
    111: "Only supports the 3rd generation protocol",
    112: "The USB shield is not inserted or the USB shield information is wrong",
    113: "The client IP address does not have login permission",
    117: "Incorrect account or password",
    118: "The device has not been initialized and cannot log in, please initialize the device first",
    119: "Login is restricted, possibly due to IP restriction, time period restriction, and validity period restriction",
    120: "Error opening audio in Render library",
    121: "Render library close audio error",
    122: "Render library control volume error",
    123: "Error in setting screen parameters of Render library",
    124: "Render library paused playback error",
    125: "Render library capture error",
    126: "Render library stepping error",
    127: "Render library set frame rate error",
    128: "Render library setting display area error",
    129: "The Render library has an error in getting the current playback time",
    140: "Group name already exists",
    141: "Group name does not exist",
    142: "The permission of the group exceeds the scope of the permission list",
    143: "There are users in the group, which cannot be deleted",
    144: "A privilege of the group is used by the user and cannot be removed",
    145: "The new group name is the same as the existing group name",
    146: "User already exists",
    147: "User does not exist",
    148: "User permission exceeds group permission",
    149: "The account is reserved and password modification is not allowed",
    150: "Incorrect password",
    151: "Password does not match",
    152: "The account is in use",
    300: "Failed to get network card configuration",
    301: "Failed to get wireless network information",
    302: "Failed to get wireless network device",
    303: "Failed to obtain active registration parameters",
    304: "Failed to get camera properties",
    305: "Failed to get infrared alarm configuration",
    306: "Failed to get audio alarm configuration",
    307: "Failed to get storage location configuration",
    308: "Failed to get mail configuration",
    309: "Unable to set temporarily",
    310: "The configuration data is invalid",
    311: "Failed to get DST configuration",
    312: "Failed to set daylight saving time configuration",
    313: "Failed to get video OSD overlay configuration",
    314: "Failed to set video OSD overlay configuration",
    315: "Failed to obtain CDMA\GPRS network configuration",
    316: "Failed to set CDMA\GPRS network configuration",
    317: "Failed to obtain IP filter configuration",
    318: "Failed to set IP filtering configuration",
    319: "Failed to obtain voice intercom encoding configuration",
    320: "Failed to set voice intercom encoding configuration",
    321: "Failed to get video package length configuration",
    322: "Failed to set the video package length configuration",
    323: "Network hard disk partitioning is not supported",
    324: "Failed to obtain information on the active registration server on the device",
    325: "Active registration redirection registration error",
    326: "Error disconnecting active registration server",
    327: "Failed to get mms configuration",
    328: "Failed to set mms configuration",
    329: "Failed to get SMS to activate wireless connection configuration",
    330: "Set SMS activation wireless connection configuration failed",
    331: "Failed to get dial-up activation wireless connection configuration",
    332: "Setup dial to activate wireless connection configuration failed",
}


class Singleton(type):
    def __init__(self, *args, **kwargs):
        self.__instance = None
        super().__init__(*args, **kwargs)

    def __call__(self, *args, **kwargs):
        if self.__instance is None:
            self.__instance = super(Singleton, self).__call__(*args, **kwargs)
        return self.__instance


class NetClient(metaclass=Singleton):
    """
    所有sdk接口都定义为该类的类方法
    all function in sdk which used define in this class
    """

    def __init__(self, *args, **kwargs):
        self._load_library()

    @classmethod
    def _load_library(cls):
        try:
            cls.sdk = windll.LoadLibrary(netsdkdllpath)
            cls.config_sdk = windll.LoadLibrary(configdllpath)
        except OSError as e:
            print("动态库加载失败")

    @classmethod
    def GetLastError(cls) -> int:
        """
        获取错误码;Return the function execution failure code
        """
        return cls.sdk.CLIENT_GetLastError() & 0x7FFFFFFF

    @classmethod
    def GetLastErrorMessage(cls) -> str:
        """
        通过错误码获取错误信息;get the error message by error code
        """
        errcode = cls.GetLastError()
        if isinstance(errcode, int) is True:
            try:
                return error_code[errcode]
            except KeyError:
                return "There is no such error code"
        else:
            return "Unknown mistake"

    @classmethod
    def InitEx(
        cls,
        call_back: fDisConnect = None,
        user_data: C_LDWORD = 0,
        init_param: NETSDK_INIT_PARAM = NETSDK_INIT_PARAM(),
    ) -> int:
        """
        初始化接口，之前须先保证该接口调用成功;SDK initialization,called before using the SDK
        :param call_back: 回调函数;call back
        :param user_data:用户数据;user data
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        init_param = pointer(init_param)
        result = cls.sdk.CLIENT_InitEx(call_back, user_data, init_param)
        if result != 1:
            print(cls.GetLastErrorMessage())
        cls.sdk.CLIENT_SetGDPREnable(True)
        return result

    @classmethod
    def Cleanup(cls):
        """
        SDK退出清理,Release sdk source
        """
        cls.sdk.CLIENT_Cleanup()

    @classmethod
    def LoginEx2(
        cls,
        ip: str,
        port: int,
        username: str,
        password: str,
        spec_cap: EM_LOGIN_SPAC_CAP_TYPE = EM_LOGIN_SPAC_CAP_TYPE.TCP,
        cap_param: c_void_p = None,
    ) -> tuple:
        ip = c_char_p(ip.encode())
        port = c_ushort(int(port))
        username = c_char_p(username.encode())
        password = c_char_p(password.encode())
        spec_cap = c_int(spec_cap)
        cap_param = c_void_p(cap_param) if cap_param is not None else None
        error = c_int(0)
        error_message = ""
        device_info = NET_DEVICEINFO_Ex()
        cls.sdk.CLIENT_LoginEx2.restype = C_LLONG
        login_id = cls.sdk.CLIENT_LoginEx2(
            ip,
            port,
            username,
            password,
            spec_cap,
            cap_param,
            byref(device_info),
            byref(error),
        )
        login_error = {
            1: "Incorrect account or password",
            2: "Username does not exist",
            3: "Login timeout",
            4: "Duplicate login",
            5: "Account is locked",
            6: "Account is blacklisted",
            7: "System busy, insufficient resources",
            8: "Subconnection failed",
            9: "Main connection failed",
            10: "Exceeded maximum number of connections",
            11: "Only supports the 3rd generation protocol",
            12: "The device is not plugged into the USB shield or the USB shield information is wrong",
            13: "The client IP address does not have login permission",
            18: "The device account is not initialized and cannot log in",
        }
        if login_id == 0:
            try:
                error_message = login_error[error.value]
            except KeyError:
                error_message = "There is no such error code"
            print(error_message)
        return login_id, device_info, error_message

    @classmethod
    def LoginWithHighLevelSecurity(
        cls,
        stuInParam: NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY,
        stuOutParam: NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY,
    ) -> tuple:
        """
        高安全级别登陆;login device with high level security
        :param stuInParam:传入参数结构体;in parameter structure
        :param stuOutParam:传出参数结构体;out parameter structure
        :return:login_id:成功返回登录句柄，失败返回0，登录成功后设备信息保存在NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY的stuDeviceInfo;
                         secssed：login id,failed：0，if login succeed,device info in stuDeviceInfo of NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY
                device_info:输出的设备信息;device information，for output parmaeter
                error_message:登录接口的错误信息；error message of login
        """
        cls.sdk.CLIENT_LoginWithHighLevelSecurity.restype = C_LLONG
        login_id = cls.sdk.CLIENT_LoginWithHighLevelSecurity(
            byref(stuInParam), byref(stuOutParam)
        )
        login_error = {
            1: "Incorrect account or password",
            2: "Username does not exist",
            3: "Login timeout",
            4: "Duplicate login",
            5: "Account is locked",
            6: "Account is blacklisted",
            7: "System busy, insufficient resources",
            8: "Subconnection failed",
            9: "Main connection failed",
            10: "Exceeded maximum number of connections",
            11: "Only supports the 3rd generation protocol",
            12: "The device is not plugged into the USB shield or the USB shield information is wrong",
            13: "The client IP address does not have login permission",
            18: "The device account is not initialized and cannot log in",
        }
        error_message = ""
        device_info = NET_DEVICEINFO_Ex()
        if login_id == 0:
            try:
                error_message = login_error[stuOutParam.nError]
            except KeyError:
                error_message = "There is no such error code"
            print(error_message)
        else:
            device_info = stuOutParam.stuDeviceInfo
        return login_id, device_info, error_message

    # @classmethod
    # def LoginWithHighLevelSecurity(cls, ip: str, port: int, username: str, password: str,
    #                                spec_cap: EM_LOGIN_SPAC_CAP_TYPE = EM_LOGIN_SPAC_CAP_TYPE.TCP,
    #                                cap_param: c_void_p = None) -> tuple:
    #     """
    #     高安全级别登陆;login device with high level security
    #     :param ip:设备IP;device IP
    #     :param port:设备端口;device port
    #     :param username:用户名;username
    #     :param password:密码;password
    #     :param spec_cap:登陆方式;login mode
    #     :param cap_param:扩展参数，只有当 spec_cap为EM_LOGIN_SPAC_CAP_TYPE.SERVER_CONN时有效;compensation parameter，nSpecCap = EM_LOGIN_SPAC_CAP_TYPE.SERVER_CONN，pCapParam fill in device serial number string(mobile dvr login)
    #     :return:login_id:成功返回登录句柄，失败返回0，登录成功后设备信息保存在NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY的stuDeviceInfo;
    #                      secssed：login id,failed：0，if login succeed,device info in stuDeviceInfo of NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY
    #             device_info:输出的设备信息;device information，for output parmaeter
    #             error_message:登录接口的错误信息；error message of login
    #     """
    #
    #     stuInParam = NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY()
    #     stuInParam.dwSize = sizeof(NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY)
    #     stuInParam.szIP = ip.encode()
    #     stuInParam.nPort = port
    #     stuInParam.szUserName = username.encode()
    #     stuInParam.szPassword = password.encode()
    #     stuInParam.emSpecCap = spec_cap
    #     stuInParam.pCapParam = cap_param
    #
    #     stuOutParam = NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY()
    #     stuOutParam.dwSize = sizeof(NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY)
    #     cls.sdk.CLIENT_LoginWithHighLevelSecurity.restype = C_LLONG
    #     login_id = cls.sdk.CLIENT_LoginWithHighLevelSecurity(byref(stuInParam), byref(stuOutParam))
    #     login_error = {
    #         1: '账号或密码错误',
    #         2: '用户名不存在',
    #         3: '登录超时',
    #         4: '重复登录',
    #         5: '帐号被锁定',
    #         6: '帐号被列入黑名单',
    #         7: '系统忙,资源不足',
    #         8: '子连接失败',
    #         9: '主连接失败',
    #         10: '超过最大连接数',
    #         11: '只支持3代协议',
    #         12: '设备未插入U盾或U盾信息错误',
    #         13: '客户端IP地址没有登录权限',
    #         18: '设备账号未初始化，无法登陆'
    #     }
    #     error_message = ''
    #     device_info = NET_DEVICEINFO_Ex()
    #     if login_id == 0:
    #         try:
    #             error_message = login_error[stuOutParam.nError]
    #         except KeyError:
    #             error_message = 'There is no such error code'
    #         print(error_message)
    #     else:
    #         device_info = stuOutParam.stuDeviceInfo
    #     return login_id, device_info, error_message

    @classmethod
    def SetAutoReconnect(cls, call_back: fHaveReConnect, user_data: C_LDWORD = None):
        """
        设置断线重连成功回调函数,设置后SDK内部断线自动重连;Set re-connection callback function after disconnection. Internal SDK  auto connect again after disconnection
        :param call_back:重连成功回调函数;Reconnect callback
        :param user_data:自定义用户数据;User data
        """
        user_data = byref(c_uint(user_data)) if user_data is not None else None
        cls.sdk.CLIENT_SetAutoReconnect(call_back, user_data)

    @classmethod
    def Logout(cls, login_id: int) -> int:
        """
        向设备注销;Log out the device
        :param login_id:登陆ID,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        login_id = C_LLONG(login_id)
        result = cls.sdk.CLIENT_Logout(login_id)
        if result == 0:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def LogOpen(cls, log_info: LOG_SET_PRINT_INFO) -> int:
        """
        打开日志功能;open log function
        :param log_info:日志相关设置参数; param of log setting
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        log_info = pointer(log_info)
        result = cls.sdk.CLIENT_LogOpen(log_info)
        if result != 1:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def LogClose(cls) -> int:
        """
        关闭日志功能;close log function
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        result = cls.sdk.CLIENT_LogClose()
        if result != 1:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def RealPlayEx(
        cls, login_id: int, channel: int, hwnd: int, play_type=SDK_RealPlayType.Realplay
    ) -> C_LLONG:
        """
        开始实时监视;Begin real-time monitor
        :param login_id:登陆句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param channel:通道号;real time monitor channel NO.(from 0).
        :param hwnd:窗口句柄;display window handle.
        :param play_type:主码流类型;realplay type
        :return:realplay_id:失败返回0，成功返回大于0的值;failed return 0, successful return the real time monitorID(real time monitor handle),as parameter of related function.
        """

        login_id = C_LLONG(login_id)
        channel = c_int(channel)
        hwnd = c_long(hwnd)
        play_type = c_int(play_type)
        cls.sdk.CLIENT_RealPlayEx.restype = C_LLONG
        realplay_id = cls.sdk.CLIENT_RealPlayEx(login_id, channel, hwnd, play_type)
        if realplay_id == 0:
            print(cls.GetLastErrorMessage())
        return realplay_id

    @classmethod
    def StopRealPlayEx(cls, realplay_id: int) -> int:
        """
        停止实时预览;stop real-time preview
        :param realplay_id:监视ID,RealPlayEx返回值;monitor handle,RealPlayEx returns value
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        realplay_id = C_LLONG(realplay_id)
        result = cls.sdk.CLIENT_StopRealPlayEx(realplay_id)
        if result == 0:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StartSearchDevicesEx(
        cls, pInBuf: NET_IN_STARTSERACH_DEVICE, pOutBuf: NET_OUT_STARTSERACH_DEVICE
    ) -> C_LLONG:
        """
        异步搜索设备;asynchronism search device
        :param pInBuf:输入参数;input param
        :param pOutBuf:输出参数;output param
        :return:搜索句柄;search handle
        """
        cls.sdk.CLIENT_StartSearchDevicesEx.restype = C_LLONG
        result = cls.sdk.CLIENT_StartSearchDevicesEx(byref(pInBuf), byref(pOutBuf))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def SearchDevicesByIPs(
        cls,
        pIpSearchInfo: DEVICE_IP_SEARCH_INFO,
        cbSearchDevices: fSearchDevicesCB,
        dwUserData: C_LDWORD,
        szLocalIp: c_char_p = None,
        dwWaitTime: C_DWORD = 5000,
    ) -> c_int:
        """
        跨网段搜索设备IP;search device ip cross VLAN
        :param pIpSearchInfo:待搜索的IP信息,ENGLISH_LANG:IP info of
        :param cbSearchDevices:回调函数,ENGLISH_LANG:Search devices call back
        :param dwUserData:用户数据,ENGLISH_LANG:User data
        :param szLocalIp:本地IP,ENGLISH_LANG:Local IP
        :param dwWaitTime:等待时间,ENGLISH_LANG:Wait time c_char_p(szLocalIp.encode())
        :return:1:搜索成功,0:搜索失败;1:search device success,0:search device failed
        """
        szLocalIp = c_char_p(szLocalIp)
        dwUserData = C_LDWORD(dwUserData)
        dwWaitTime = C_DWORD(dwWaitTime)
        result = cls.sdk.CLIENT_SearchDevicesByIPs(
            byref(pIpSearchInfo), cbSearchDevices, dwUserData, szLocalIp, dwWaitTime
        )
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StopSearchDevices(cls, lSearchHandle: C_LLONG) -> c_int:
        """
        异步停止搜索设备;stop asynchronism search IPC, NVS and etc in LAN
        :param lSearchHandle:搜索句柄;search handle
        :return:1:停止搜索成功,0:停止搜索失败;1:stop search device success,0:stop search device failed
        """
        lSearchHandle = C_LLONG(lSearchHandle)
        result = cls.sdk.CLIENT_StopSearchDevices(lSearchHandle)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def InitDevAccount(
        cls,
        pInitAccountIn: NET_IN_INIT_DEVICE_ACCOUNT,
        pInitAccountOut: NET_OUT_INIT_DEVICE_ACCOUNT,
        dwWaitTime: int = 5000,
        szLocalIp: c_char_p = None,
    ) -> c_int:
        """
        初始化设备账户;init account
        :param pInitAccountIn:输入参数结构体NET_IN_INIT_DEVICE_ACCOUNT;input param,corresponding to NET_IN_INIT_DEVICE_ACCOUNT
        :param pInitAccountOut:输出参数结构体NET_OUT_INIT_DEVICE_ACCOUNT;output param,corresponding to NET_OUT_INIT_DEVICE_ACCOUNT
        :return:1:初始化设备账户成功,0:初始化设备账户失败;1:Init device account success,0:Init device account failed
        """
        szLocalIp = c_char_p(szLocalIp)
        result = cls.sdk.CLIENT_InitDevAccount(
            byref(pInitAccountIn), byref(pInitAccountOut), dwWaitTime, szLocalIp
        )
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def RealLoadPictureEx(
        cls,
        lLoginID: C_LLONG,
        nChannelID: c_int,
        dwAlarmType: c_ulong,
        bNeedPicFile: c_int,
        cbAnalyzerData: fAnalyzerDataCallBack,
        dwUser: C_LDWORD = 0,
        reserved: c_void_p = None,
    ) -> C_LLONG:
        """
        实时上传智能分析数据图片(扩展接口,bNeedPicFile表示是否订阅图片文件); real load picture of intelligent analysis(expand interface: 'bNeedPicFile == true' instruct load picture file, 'bNeedPicFile == false' instruct not load picture file )
        :param lLoginID:登陆ID; login returns value
        :param nChannelID:通道号; channel id
        :param dwAlarmType:事件类型,参考EM_EVENT_IVS_TYPE; event type see EM_EVENT_IVS_TYPE
        :param bNeedPicFile:是否订阅图片文件; subscribe image file or not,ture-yes,return intelligent image info during callback function,false not return intelligent image info during callback function
        :param cbAnalyzerData:事件回调函数; intelligent data analysis callback
        :param dwUser:用户数据; user data
        :param reserved:保留参数; reserved
        :return:订阅句柄;Handle
        """
        lLoginID = C_LLONG(lLoginID)
        nChannelID = c_int(nChannelID)
        dwAlarmType = c_ulong(dwAlarmType)
        bNeedPicFile = c_int(bNeedPicFile)
        dwUser = C_LDWORD(dwUser)
        reserved = c_void_p(reserved)
        cls.sdk.CLIENT_RealLoadPictureEx.restype = C_LLONG
        event_id = cls.sdk.CLIENT_RealLoadPictureEx(
            lLoginID,
            nChannelID,
            dwAlarmType,
            bNeedPicFile,
            cbAnalyzerData,
            dwUser,
            reserved,
        )
        if not event_id:
            print(cls.GetLastErrorMessage())
        return event_id

    @classmethod
    def StopLoadPic(cls, lAnalyzerHandle: C_LLONG) -> c_int:
        """
        停止上传智能分析数据－图片;stop asynchronism search IPC, NVS and etc in LAN
        :param lAnalyzerHandle:订阅句柄,RealLoadPictureEx接口返回值;handle,the value is returned by RealLoadPictureEx
        :return:1:停止订阅成功,0:停止订阅失败;1:StopLoadPic success,0:StopLoadPic failed
        """
        lAnalyzerHandle = C_LLONG(lAnalyzerHandle)
        result = cls.sdk.CLIENT_StopLoadPic(lAnalyzerHandle)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def SetDeviceMode(cls, login_id: int, emType: int, value: c_void_p) -> c_int:
        """
        设置语音对讲模式,客户端方式还是服务器方式(pValue内存由用户申请释放，大小参照EM_USEDEV_MODE对应的结构体); Set audio talk mode(client-end mode or server mode), user malloc pValue's memory,please refer to the corresponding structure of EM_USEDEV_MODE
        :param login_id:登陆句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param emType:工作模式类型; user work mode
        :param value:emType对应的结构体; support these emType
        :return:成功：1，失败：0；succeed：1，failed：0
        """
        if login_id == 0:
            return
        login_id = C_LLONG(login_id)
        emType = c_int(emType)
        p_value = pointer(value)
        result = cls.sdk.CLIENT_SetDeviceMode(login_id, emType, p_value)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def QueryRecordFile(
        cls,
        login_id: int,
        channel_id: int,
        recordfile_type: int,
        start_time: NET_TIME,
        end_time: NET_TIME,
        card_id: str,
        wait_time: int,
        is_querybytime: bool,
    ) -> tuple:
        """
        查询时间段内的所有录像文件; Search all recorded file sin the specified periods
        :param login_id:登陆句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param channel_id:查询通道号; user work mode
        :param recordfile_type:查询类型，参考EM_QUERY_RECORD_TYPE; type of record file,see EM_QUERY_RECORD_TYPE
        :param start_time:起始时间; start time
        :param end_time:结束时间; end time
        :param card_id:卡号; card id
        :param wait_time:超时时间; wait timr
        :param is_querybytime:是否是按时间查询; query by time or not
        :return:result:成功：1，失败：0；succeed：1，failed：0
                file_count:返回文件个数; the file count of query
                recordfile_infos:文件信息; record file infos
        """
        if login_id == 0:
            return
        login_id = C_LLONG(login_id)
        channel_id = c_int(channel_id)
        recordfile_type = c_int(recordfile_type)
        recordfile_infos = NET_RECORDFILE_INFO * 5000
        p_recordfile_infos = recordfile_infos()
        maxlen = sizeof(NET_RECORDFILE_INFO) * 5000
        maxlen = c_int(maxlen)
        file_count = c_int(0)
        is_querybytime = c_bool(is_querybytime)

        result = cls.sdk.CLIENT_QueryRecordFile(
            login_id,
            channel_id,
            recordfile_type,
            byref(start_time),
            byref(end_time),
            card_id,
            p_recordfile_infos,
            maxlen,
            byref(file_count),
            wait_time,
            is_querybytime,
        )
        if not result:
            print(cls.GetLastErrorMessage())
        else:
            file_count = file_count.value
            file_count = 5000 if file_count > 5000 else file_count
            recordfile_infos = p_recordfile_infos
        return result, file_count, recordfile_infos

    @classmethod
    def PlayBackByTimeEx(
        cls,
        login_id: int,
        channel_id: int,
        start_time: NET_TIME,
        end_time: NET_TIME,
        hwnd: C_LONG,
        callback_timedownloadpos: fDownLoadPosCallBack,
        time_UserData: C_LDWORD,
        callback_timedownloaddata: fDataCallBack,
        data_UserData: C_LDWORD,
    ) -> int:
        """
        查询时间段内的所有录像文件; Search all recorded file sin the specified periods
        :param login_id:登陆句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param channel_id:查询通道号; user work mode
        :param in_param:输入参数结构体NET_IN_PLAY_BACK_BY_TIME_INFO; input param,corresponding to NET_IN_PLAY_BACK_BY_TIME_INFO
        :param out_param:输出参数结构体NET_OUT_PLAY_BACK_BY_TIME_INFO; output param,corresponding to NET_OUT_PLAY_BACK_BY_TIME_INFO
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        if login_id == 0:
            return 0
        login_id = C_LLONG(login_id)
        channel_id = c_int(channel_id)
        hwnd = C_LONG(hwnd)
        cls.sdk.CLIENT_PlayBackByTimeEx.restype = C_LLONG
        result = cls.sdk.CLIENT_PlayBackByTimeEx(
            login_id,
            channel_id,
            byref(start_time),
            byref(end_time),
            hwnd,
            callback_timedownloadpos,
            time_UserData,
            callback_timedownloaddata,
            data_UserData,
        )
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def PlayBackByTimeEx2(
        cls,
        login_id: int,
        channel_id: int,
        in_param: NET_IN_PLAY_BACK_BY_TIME_INFO,
        out_param: NET_OUT_PLAY_BACK_BY_TIME_INFO,
    ) -> int:
        """
        查询时间段内的所有录像文件; Search all recorded file sin the specified periods
        :param login_id:登陆句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param channel_id:查询通道号; user work mode
        :param in_param:输入参数结构体NET_IN_PLAY_BACK_BY_TIME_INFO; input param,corresponding to NET_IN_PLAY_BACK_BY_TIME_INFO
        :param out_param:输出参数结构体NET_OUT_PLAY_BACK_BY_TIME_INFO; output param,corresponding to NET_OUT_PLAY_BACK_BY_TIME_INFO
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        if login_id == 0:
            return 0
        login_id = C_LLONG(login_id)
        channel_id = c_int(channel_id)
        in_param = byref(in_param)
        out_param = byref(out_param)
        cls.sdk.CLIENT_PlayBackByTimeEx2.restype = C_LLONG
        result = cls.sdk.CLIENT_PlayBackByTimeEx2(
            login_id, channel_id, in_param, out_param
        )
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StopPlayBack(cls, playback_id: int) -> int:
        """
        停止回放; stop palyback
        :param playback_id:回放句柄, PlayBackByTimeEx2的返回值； palyback handle，PlayBackByTimeEx2's returns value
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        if playback_id == 0:
            return
        playback_id = C_LLONG(playback_id)
        result = cls.sdk.CLIENT_StopPlayBack(playback_id)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def PausePlayBack(cls, playback_id: int, is_pause: bool) -> int:
        """
        查询时间段内的所有录像文件; Search all recorded file sin the specified periods
        :param playback_id:回放句柄, PlayBackByTimeEx2的返回值； palyback handle，PlayBackByTimeEx2's returns value
        :param is_pause:操作动作，暂停还是继续; opreate type， pause or continue
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        if playback_id == 0:
            return 0
        playback_id = C_LLONG(playback_id)
        is_pause = c_int(is_pause)
        result = cls.sdk.CLIENT_PausePlayBack(playback_id, is_pause)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def DownloadByTimeEx(
        cls,
        login_id: int,
        channel_id: int,
        recordfile_type: int,
        start_time: NET_TIME,
        end_time: NET_TIME,
        save_filename: str,
        callback_timedownloadpos: fTimeDownLoadPosCallBack,
        time_UserData: C_LDWORD,
        callback_timedownloaddata: fDataCallBack,
        data_UserData: C_LDWORD,
        pReserved: int = 0,
    ) -> int:
        """
        通过时间下载录像--扩展; Through the time to download the video - extension
        :param login_id:登陆句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param channel_id:查询通道号; user work mode
        :param recordfile_type:查询类型，参考EM_QUERY_RECORD_TYPE; type of record file,see EM_QUERY_RECORD_TYPE
        :param start_time:起始时间; start time
        :param end_time:结束时间; end time
        :param save_filename:保存录像的文件名; save file name
        :param callback_timedownloadpos:下载的时间回调; download by time's pos callback
        :param time_UserData:用户数据; callback_timedownloadpos's user data
        :param callback_timedownloaddata:下载的数据回调; video data's callback
        :param data_UserData:用户数据; callback_timedownloaddata's user data
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        if login_id == 0:
            return
        login_id = C_LLONG(login_id)
        channel_id = c_int(channel_id)
        save_filename = c_char_p(save_filename.encode("gbk"))
        pReserved = pointer(c_int(pReserved))
        cls.sdk.CLIENT_DownloadByTimeEx.restype = C_LLONG
        result = cls.sdk.CLIENT_DownloadByTimeEx(
            login_id,
            channel_id,
            recordfile_type,
            byref(start_time),
            byref(end_time),
            save_filename,
            callback_timedownloadpos,
            time_UserData,
            callback_timedownloaddata,
            data_UserData,
            pReserved,
        )
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StopDownload(cls, download_id: int) -> int:
        """
        停止录像下载;  Stop record download
        :param download_id:下载句柄, DownloadByTimeEx的返回值； download handle，DownloadByTimeEx's returns value
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        if download_id == 0:
            return
        download_id = C_LLONG(download_id)
        result = cls.sdk.CLIENT_StopDownload(download_id)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def GetDevConfig(
        cls,
        login_id: C_LLONG,
        cfg_type: C_DWORD,
        channel_id: C_LONG,
        out_buffer: C_LLONG,
        outbuffer_size: C_DWORD,
        wait_time: int = 5000,
    ) -> int:
        """
        查询配置信息； Search configuration information
        :param login_id:登陆句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param cfg_type:查询类型，参考EM_QUERY_RECORD_TYPE; type of record file,see EM_QUERY_RECORD_TYPE
        :param channel_id:查询通道号; user work mode
        :param out_buffer:获取的结构体数据; struct data of output
        :param outbuffer_size:out_buffer数据长度; size of out_buffer
        :param wait_time:超时时间; wait time
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        if login_id == 0:
            return
        login_id = C_LLONG(login_id)
        channel_id = C_LONG(channel_id)
        out_buffer = pointer(out_buffer)
        outbuffer_size = C_DWORD(outbuffer_size)
        bytes_returned = c_uint(0)
        result = cls.sdk.CLIENT_GetDevConfig(
            login_id,
            cfg_type,
            channel_id,
            out_buffer,
            outbuffer_size,
            byref(bytes_returned),
            wait_time,
        )
        if not result:
            print(cls.GetLastErrorMessage())
        if outbuffer_size.value != bytes_returned.value:
            print("返回结果出错(Return value is wrong!)")
            result = 0
        return result

    @classmethod
    def SetDevConfig(
        cls,
        login_id: C_LLONG,
        cfg_type: C_DWORD,
        channel_id: C_LONG,
        in_buffer: C_LLONG,
        inbuffer_size: C_DWORD,
        wait_time: int = 5000,
    ) -> int:
        """
        设置配置信息; Set configuration information
        :param login_id:登陆句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param cfg_type:查询类型，参考EM_QUERY_RECORD_TYPE; type of record file,see EM_QUERY_RECORD_TYPE
        :param channel_id:查询通道号; user work mode
        :param in_buffer:传入的结构体数据; struct data of input
        :param inbuffer_size:in_buffer数据长度; size of in_buffer
        :param wait_time:超时时间; wait time
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        if login_id == 0:
            return
        login_id = C_LLONG(login_id)
        channel_id = C_LONG(channel_id)
        in_buffer = pointer(in_buffer)
        inbuffer_size = C_DWORD(inbuffer_size)
        result = cls.sdk.CLIENT_SetDevConfig(
            login_id, cfg_type, channel_id, in_buffer, inbuffer_size, wait_time
        )
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def RebootDev(cls, login_id: int) -> int:
        """
        重启设备;  Reboot device
        :param login_id:登陆句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        if login_id == 0:
            return
        login_id = C_LLONG(login_id)
        result = cls.sdk.CLIENT_RebootDev(login_id)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def SetSnapRevCallBack(cls, OnSnapRevMessage: fSnapRev, dwUser: C_LDWORD) -> None:
        """
        设置抓图回调函数;Set snapshot callback function
        :param OnSnapRevMessage:抓图回调;snap receive message
        :param dwUser:用户数据；user data
        :return:None
        """
        dwUser = C_LDWORD(dwUser)
        cls.sdk.CLIENT_SetSnapRevCallBack(OnSnapRevMessage, dwUser)

    @classmethod
    def SnapPictureEx(cls, lLoginID: C_LLONG, par: SNAP_PARAMS, reserved=0) -> c_int:
        """
        抓图请求扩展接口;Snapshot request--extensive
        :param lLoginID:登陆句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param par:抓图参数结构体;Snapshot parameter structure
        :param reserved:保留字段；reserved
        :return:空；None
        """
        lLoginID = C_LLONG(lLoginID)
        par = pointer(par)
        reserved = pointer(c_int(reserved))
        result = cls.sdk.CLIENT_SnapPictureEx(lLoginID, par, reserved)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StartListenEx(cls, lLoginID: C_LLONG) -> c_int:
        """
        向设备订阅报警--扩展;subscribe alarm---extensive
        :param lLoginID:登陆句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :return:1:成功，0：失败；1：success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_StartListenEx(lLoginID)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def SetDVRMessCallBackEx1(
        cls, cbMessage: fMessCallBackEx1, dwUser: C_LDWORD
    ) -> None:
        """
        设置报警回调函数;Set alarm callback function
        :param cbMessage:消息回调函数原形(pBuf内存由SDK内部申请释放); Alarm message callback function original shape
        :param dwUser:用户数据；user data
        :return:空；None
        """
        dwUser = C_LDWORD(dwUser)
        cls.sdk.CLIENT_SetDVRMessCallBackEx1(cbMessage, dwUser)

    @classmethod
    def StopListen(cls, lLoginID: C_LLONG) -> c_int:
        """
        停止订阅报警;Stop subscribe alarm
        :param lLoginID: 登陆句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :return:1:成功，0：失败；1：success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_StopListen(lLoginID)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def RenderPrivateData(cls, realplay_id: C_LLONG, bTrue: bool) -> c_int:
        """
        显示私有数据，例如规则框，规则框报警，移动侦测等;Stop subscribe alarm
        :param realplay_id:监视ID,RealPlayEx返回值;monitor handle,RealPlayEx returns value
        :param lLoginID: 播放句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :return:1:成功，0：失败；1：success,0:failed
        """
        realplay_id = C_LLONG(realplay_id)
        bTrue = c_int(bTrue)
        result = cls.sdk.CLIENT_RenderPrivateData(realplay_id, bTrue)
        if not result:
            print(cls.GetLastErrorMessage())
        return result


__all__ = [
    "NetSDK",
]
