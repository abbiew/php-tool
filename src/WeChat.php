<?php

/**
 * Created by PhpStorm.
 * User: polar bear
 * Date: 2018/7/19
 * Time: 10:21
 */
namespace PolarBear\Tool;

use App\RedisManager;
use Swoole\Client\CURL;
use App\TradeInCar\Constant;

class WeChat
{
    //获取openid的url
    public static $miniProgramGetOpenidUrl = 'https://api.weixin.qq.com/sns/jscode2session?appid=%s&secret=%s&js_code=%s&grant_type=authorization_code';
    //获取access_token的url
    public static $miniProgramGetAccessTokenUrl = 'https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=%s&secret=%s';
    //access_token redis key common part
    public static $accessTokenRedisKey = "chezhu_weChat_mini_program_access_token_redis_key_appid:%s_index:%s";
    //get userinfo url 非授权token
    public static $userInfoUrl = "https://api.weixin.qq.com/cgi-bin/user/info?access_token=%s&openid=%s&lang=zh_CN";

    public static $userSessionKeyRedisKey = 'trade_in_car_mini_apps_session_key_appid=%s_openid=%s';
    //获取公众号authorize access_token的url
    public static $officialAccountsAuthorizeAccessTokenUrl = 'https://api.weixin.qq.com/sns/oauth2/access_token?appid=%s&secret=%s&code=%s&grant_type=authorization_code';
    //获取用户信息，次数需要的token为授权token
    public static $authorizeUserInfoUrl = 'https://api.weixin.qq.com/sns/userinfo?access_token=%s&openid=%s&lang=zh_CN';

    public const OPEN_ID_LENGTH = 28; //openid最小长度
    public const UNION_ID_LENGTH = 28; //unionid最小长度

    /**
     * 获取微信用户openId
     * @param $jsCode string 前端获取的jsCode
    */
    public static function weChatGetMiniProgramUserOpenid($jsCode,$cacheSessionKey = true){
        $ret = ['code'=>0, 'msg'=>'ok'];
        try{
            if (empty($jsCode)){
                throw new \Exception('jsCode错误',10002);
            }
            $miniProgramInfo = ['appid'=>'zzzz', 'secret'=>'adasdasd']; //此处为小程序appid和secret,可根据自己的进行配置
            $url = sprintf(self::$miniProgramGetOpenidUrl,$miniProgramInfo['appid'],$miniProgramInfo['secret'],$jsCode);
            $curl = new CURL();
            $resp = $curl->get($url);
            //记录返回log
            $respArr = json_decode($resp,true);
            if(isset($respArr['openid'])){
                //此处可记录session_key信息
                /*if (!empty($respArr['session_key']) && $cacheSessionKey) {
                    $redisKey = sprintf(self::$userSessionKeyRedisKey, $miniProgramInfo['appid'], $respArr['openid']);
                    $redisObj = RedisManager::getInstance();
                    $redisObj->set($redisKey, $respArr['session_key'], 3600);
                }*/
                $ret['data'] = $respArr;
            }else{ //失败
                $errMsg = '获取openid失败';
                $errCode = 10003;
                if (isset($respArr['errcode'])){
                    $errMsg .= ',respMsg:' . ($respArr['errmsg'] ?? '');
                    $errMsg .= ',respCode:' . $respArr['errcode'];
                }else{
                    $errMsg .= ',curlMsg:' . $curl->errMsg. ',curlCode:' . $curl->errCode;
                }
                throw new \Exception($errMsg, $errCode);
            }
        }catch (\Throwable $e){
            $ret['code'] = $e->getCode();
            $ret['msg'] = $e->getMessage();
        }
        return $ret;
    }

    //对emoji表情转义
    public static function emoji_encode($str){
        $strEncode = '';
        $length = mb_strlen($str,'utf-8');

        for ($i=0; $i < $length; $i++) {
            $_tmpStr = mb_substr($str,$i,1,'utf-8');
            if(strlen($_tmpStr) >= 4){
                $strEncode .= '[[EMOJI:'.rawurlencode($_tmpStr).']]';
            }else{
                $strEncode .= $_tmpStr;
            }
        }

        return $strEncode;
    }
    //对emoji表情转反义
    public static function emoji_decode($str){
        $strDecode = preg_replace_callback('|\[\[EMOJI:(.*?)\]\]|', function($matches){
            return rawurldecode($matches[1]);
        }, $str);

        return $strDecode;
    }

    //刷新access_token
    public static function weChatRefreshMiniProgramAccessToken($miniProgram){
        $ret = ['code'=>0, 'msg'=>'ok'];
        try{
            //获取小程序appid和secret
            $miniProgramInfo = ['appid'=>'zzzz', 'secret'=>'adasdasd'];
            if (empty($miniProgramInfo)){
                throw new \Exception('参数错误',10001);
            }
            $appid = $miniProgramInfo['appid'];
            $redisObj = RedisManager::getInstance();
            //加刷新锁，避免重复刷新
            $redisLockKey = 'chezhu_wechat_refresh_access_token_lock_redis_key_appid:' . $appid;
            if ($redisObj->cache->rawCommand('SET',$redisLockKey,1,'EX',30,'NX')){
                $curl = new CURL();
                $url = sprintf(self::$miniProgramGetAccessTokenUrl, $appid, $miniProgramInfo['secret']);
                $resp = $curl->get($url,null,60);
                $respArr = json_decode($resp,true);
                if (isset($respArr['access_token'])){
                    //设置获取时间
                    $respArr['fetch_time'] = time() - 60; //时间提前一些，主要是有处理时间等
                    //写入redis
                    $redisAccessTokenKey = sprintf(self::$accessTokenRedisKey, $appid, $miniProgram);
                    $redisObj->set($redisAccessTokenKey, json_encode($respArr));
                    $ret['data'] = $respArr['access_token'];
                }else{
                    $errMsg = '刷新'.$miniProgramInfo['name'].'access_token失败';
                    $errCode = 10003;
                    if (isset($respArr['errcode'])){
                        $errMsg .= ',respMsg:' . ($respArr['errmsg'] ?? '');
                        $errMsg .= ',respCode:' . $respArr['errcode'];
                    }else{
                        $errMsg .= ',curlMsg:' . $curl->errMsg. ',curlCode:' . $curl->errCode;
                    }
                    throw new \Exception($errMsg, $errCode);
                }
            }else{
                throw new \Exception('refresh is locking',10002);
            }
        }catch (\Throwable $e){
            $ret['code'] = $e->getCode();
            $ret['msg'] = $e->getMessage();
        }
        //写日志
        //返回
        return $ret;
    }
    //是否需要刷新access_token
    public static function monitorMiniProgramAccessToken($miniProgram){
        $ret = ['code'=>0, 'msg'=>'ok'];
        try{
            $miniProgramInfo = ['appid'=>'zzzz', 'secret'=>'adasdasd'];
            $redisObj = RedisManager::getInstance();
            $monitorLockKey = 'chezhu_wechat_monitor_miniprogram_access_token_lock_redis_key_appid:' . $miniProgramInfo['appid'] .'_index:' . $miniProgram;
            if ($redisObj->cache->rawCommand('SET',$monitorLockKey,1,'EX',30,'NX')) {
                $redisKey = sprintf(self::$accessTokenRedisKey, $miniProgramInfo['appid'], $miniProgram);
                $tokenInfo = $redisObj->get($redisKey);
                $tokenInfoArr = json_decode($tokenInfo, true);
                //为空或者已超时(提前认为超时)，需重新获取
                if (empty($tokenInfoArr) || (time() - $tokenInfoArr['fetch_time'] + 60) >= $tokenInfoArr['expires_in']) {
                    $refreshRet = self::weChatRefreshMiniProgramAccessToken($miniProgram);
                    if ($refreshRet['code'] != 0) {
                        throw new \Exception('refresh access token fail', 10002);
                    }
                }
            }else{
                throw new \Exception('monitor is locking',10003);
            }
        }catch (\Throwable $e){
            $ret['code'] = $e->getCode();
            $ret['msg'] = $e->getMessage();
        }
        //如果是成功或者非lock失败，则删除lock
        //写日志
        return $ret;
    }
    //获取公众号用户信息，此处token为authorize token
    public static function getAuthorizeUserInfo($accessToken,$openid){
        $url = sprintf(self::$authorizeUserInfoUrl, $accessToken, $openid);
        $curl = new CURL();
        $resp = $curl->get($url,null,10);
        $respArr = json_decode($resp,true);
        $log = __CLASS__.'::'.__METHOD__.',token:' . $accessToken . ',openid:' . $openid . ',ret:' . $resp;
        $fileName = 'get_authorize_user_info_' . date('Ymd') .'.log';
        //self::log($log, $fileName);
        if (empty($respArr) || isset($respArr['errcode'])){
            $errCode = $respArr['errcode'] ?? $curl->errCode;
            $errMsg = $respArr['errmsg'] ?? $curl->errMsg;
            return ['code'=>$errCode, 'msg'=>$errMsg];
        }else{
            return ['code'=>0, 'msg'=>'ok', 'data'=>$respArr];
        }
    }
    //解密小程序数据
    public static function decryptMiniAppsData($openId,$type,$encryptedData, $iv){
        $ret = ['code'=>0, 'msg'=>'ok'];
        try{
            $miniAppInfo = ['appid'=>'zzzz', 'secret'=>'adasdasd'];
            if (empty($miniAppInfo)){
                throw new \Exception('type is error',10001);
            }
            if (empty($openId)){
                throw new \Exception('open id is empty',10002);
            }
            if (empty($encryptedData)){
                throw new \Exception('encrypted data is empty',10003);
            }
            if (empty($iv)){
                throw new \Exception('iv is empty',10004);
            }
            $redisObj = RedisManager::getInstance();
            $getSessionRedisKey = sprintf(WeChat::$userSessionKeyRedisKey,$miniAppInfo['appid'],$openId);
            $sessionKey = $redisObj->get($getSessionRedisKey);
            if (empty($sessionKey)){
                throw new \Exception('session key is empty',10005);
            }
            //解密
            $bizDataCrypt = new \App\API\WXBizDataCrypt($miniAppInfo['appid'], $sessionKey);
            $decryptErrCode = $bizDataCrypt->decryptData($encryptedData, $iv, $decryptData);
            if ($decryptErrCode != 0) {
                throw new \Exception('解密失败', 10006);
            }
            $decryptData = json_decode($decryptData,true);
            if ($decryptData['openId'] != $openId) {
                throw new \Exception('数据错误', 10007);
            }
            $ret['data'] = $decryptData;
        }catch (\Throwable $e){
            $ret['msg'] = $e->getMessage();
            $ret['code'] = $e->getCode();
        }
        $log = __CLASS__.'::'.__METHOD__.',openId:' . $openId .',type:' . $type .',encryptedData:'. $encryptedData .',iv:'. $iv .',ret:' . json_encode($ret,JSON_UNESCAPED_UNICODE);
        if ($ret['code'] != 0 && isset($decryptData)){
            $log .= ',decryptData:' . json_encode($decryptData,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
        }
        $logFileName = 'decrypt_mini_apps_data_'. date('Ymd') .'.log';
        self::log($log, $logFileName);
        return $ret;
    }

    /**
     * 获取公众号authorize access_token
     * @param $code string code
     * @param $miniProgram int index
     */
    public static function getOfficialAccountAuthorizeAccessToken($code,$miniProgram){
        $ret = ['code'=>0,'msg'=>''];
        try{
            $officialAccountInfo = ['appid'=>'zzzz', 'secret'=>'adasdasd'];
            if (empty($code) || empty($officialAccountInfo)){
                throw new \Exception('参数错误',10001);
            }
            $url = sprintf(self::$officialAccountsAuthorizeAccessTokenUrl,$officialAccountInfo['appid'],$officialAccountInfo['secret'],$code);
            $curl = new CURL();
            $resp = $curl->get($url,null,10);
            $respArr = json_decode($resp,true);
            if (isset($respArr['access_token'])){
                $ret['data'] = $respArr;
            }else{
                $errMsg = '获取用户授权access_token失败';
                $errCode = 10002;
                if (isset($respArr['errcode'])){
                    $errMsg .= ',respMsg:' . ($respArr['errmsg'] ?? '');
                    $errMsg .= ',respCode:' . $respArr['errcode'];
                }else{
                    $errMsg .= ',curlMsg:' . $curl->errMsg. ',curlCode:' . $curl->errCode;
                }
                throw new \Exception($errMsg, $errCode);
            }
        }catch (\Throwable $e){
            $ret['code'] = $e->getCode();
            $ret['msg'] = $e->getMessage();
        }
        $log = 'get official accounts authorize access token,code:' . $code .',miniProgram:'. $miniProgram .',ret:'. json_encode($ret,JSON_UNESCAPED_UNICODE);
        if (isset($resp)){
            $log .= ',resp:' . $resp;
        }
        $logFileName = 'get_official_account_authorize_access_token_'.$miniProgram . '_'. date('Ymd') .'.log';
        self::log($log,$logFileName);
        return $ret;
    }
}
