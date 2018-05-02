<?php
namespace BigBear\Tool;

class Validate
{
    static $regx = [
        'mobile' => '/^((13[0-9]|14[579]|15[0-3,5-9]|16[6]|17[0135678]|18[0-9]|19[89])\d{8})$/',//不包括物联网
        'mobile_simple' => '/^\d{11}$/',//简单的手机验证，只验证是11位数字
        'telephone' => '/^((0[0-9]{2,3}\-)?([2-9][0-9]{6,7})+(\-[0-9]{1,4})?)$/',//固定电话号码
        'chinese'=>'/^[\x{4e00}-\x{9fa5}]+$/u',//utf-8中文字符串
        'email'=>'/^[\w-\.]+@[\w-]+(\.(\w)+)*(\.(\w){2,4})$/',
    ];
    static $dateFormats = [
        'Y-m-d', 'Y/m/d', 'Y-m-d H:i:s', 'Y/m/d H:i:s', 'Y-n-d', 'Y/n/d', 'Y-n-d H:i:s', 'Y/n/d H:i:s'
    ];
    /**
     * 正则验证
     * @param $regx
     * @param $input
     * @return bool|string
     */
    static function regx($regx, $input)
    {
        $n = preg_match($regx, $input, $match);
        if ($n === 0)
        {
            return false;
        }
        else
        {
            return $match[0];
        }
    }

    static function isVersion($ver)
    {
        return self::check('version', $ver);
    }

    static function check($ctype, $input)
    {
        if (isset(self::$regx[$ctype]))
        {
            return self::regx(self::$regx[$ctype], $input);
        }
        else
        {
            return self::$ctype($input);
        }
    }

    /**
     * 检查数组是否缺少某些Key
     * @param array $array
     * @param array $keys
     *
     * @return bool
     */
    static function checkLacks(array $array, array $keys)
    {
        foreach($keys as $k)
        {
            if (empty($array[$k]))
            {
                return false;
            }
        }
        return true;
    }

    /**
     * 验证邮箱
     * @param $str
     * @return false or $str
     */
    static function filterEmail($str)
    {
        return filter_var($str, FILTER_VALIDATE_EMAIL);
    }

    /**
     * 验证字符串格式
     * @param $str
     * @return false or $str
     */
    static function string($str)
    {
        return filter_var($str, FILTER_DEFAULT);
    }
    /**
     * 验证是否为URL
     * @param $str
     * @return false or $str
     */
    static function url($str)
    {
        return filter_var($str, FILTER_VALIDATE_URL);
    }
    /**
     * 验证是否为domain
     * @param $str
     * @return false or $str
     */
    static function domain($str)
    {
        return filter_var($str, FILTER_VALIDATE_DOMAIN);
    }
    /**
     * 过滤HTML，使参数为纯文本
     * @param $str
     * @return false or $str
     */
    static function text($str)
    {
        return filter_var($str, FILTER_SANITIZE_STRING);
    }
    /**
     * 检测是否为gb2312中文字符串
     * @param $str
     * @return false or $str
     */
    static function chinese_gb($str)
    {
        $n =  preg_match("/^[".chr(0xa1)."-".chr(0xff)."]+$/",$str,$match);
        if($n===0) return false;
        else return $match[0];
    }
    /**
     * 检测是否为自然字符串（可是中文，字符串，下划线，数字），不包含特殊字符串，只支持utf-8或者gb2312
     * @param $str
     * @return false or $str
     */
    static function realstring($str,$encode='utf8')
    {
        if($encode=='utf8') $n = preg_match('/^[\x{4e00}-\x{9fa5}|a-z|0-9|A-Z]+$/u',$str,$match);
        else $n = preg_match("/^[".chr(0xa1)."-".chr(0xff)."|a-z|0-9|A-Z]+$/",$str,$match);
        if($n===0) return false;
        else return $match[0];
    }
    /**
     * 检测是否一个英文单词，不含空格和其他特殊字符
     * @param $str
     * @return false or $str
     */
    static function word($str, $other='')
    {
        $n = preg_match("/^([a-zA-Z_{$other}]*)$/",$str,$match);
        if($n===0) return false;
        else return $match[0];
    }

    /**
     * 检查是否ASSIC码
     * @param $value
     * @return true or false
     */
    static function assic($value)
    {
        $len = strlen($value);
        for ($i = 0; $i < $len; $i++)
        {
            $ord = ord(substr($value, $i, 1));
            if ($ord > 127) return false;
        }
        return $value;
    }

    /**
     * IP地址
     * @param $value
     * @return bool
     */
    static function ip($value)
    {
        $arr = explode('.', $value);
        if (count($arr) != 4)
        {
            return false;
        }
        //第一个和第四个不能为0或255
        if (($arr[0] < 1 or $arr[0] > 254) or ($arr[3] < 1 or $arr[3] > 254))
        {
            return false;
        }
        //中间2个可以为0,但不能超过254
        if (($arr[1] < 0 or $arr[1] > 254) or ($arr[2] < 0 or $arr[2] > 254))
        {
            return false;
        }
        return true;
    }

    /**
     * 验证是否为ip
     * @param $str
     * @return false or $str
     */
    static function filterIP($str)
    {
        return filter_var($str, FILTER_VALIDATE_IP);
    }

    /**
     * 检查值如果为空则设置为默认值
     * @param $value
     * @param $default
     * @return unknown_type
     */
    static function value_default($value,$default)
    {
        if(empty($value)) return $default;
        else return $value;
    }

    /**
     * 验证日期格式，默认支持Y-m-d H:i:s Y/m/d H:i:s，可自己传入格式
     * @param $value string
     * @param $format array
     * @return bool
     */
    static function verDate($date,$formats = [])
    {
        $unixTime = strtotime($date);
        if (!$unixTime) { //strtotime转换不对，日期格式显然不对。
            return false;
        }
        //校验日期的有效性，只要满足其中一个格式就OK
        $formats = empty($formats) ? self::$dateFormats : $formats;
        foreach ($formats as $format) {
            if (date($format, $unixTime) == $date) {
                return true;
            }
        }
        return false;
    }
}
