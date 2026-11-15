package io.github.try2love.codexbridge;

import java.net.URI;
import java.net.URLDecoder;
import java.util.LinkedHashMap;
import java.util.Map;

/** Public device identity only. Pairing links never contain account credentials. */
final class ZCodePairing {
 final String sid,mid,name;
 ZCodePairing(String sid,String mid,String name){this.sid=sid;this.mid=mid;this.name=name;}
 static boolean accepts(String value){try{URI u=new URI(value.trim());return "zcode.z.ai".equalsIgnoreCase(u.getHost());}catch(Exception invalid){return false;}}
 static ZCodePairing parse(String value)throws Exception {
  URI u=new URI(value.trim());
  if(!"https".equals(u.getScheme())||!"zcode.z.ai".equalsIgnoreCase(u.getHost())||u.getRawUserInfo()!=null||u.getPort()!=-1||!"/remote/v4".equals(u.getRawPath())||u.getRawFragment()!=null||u.getRawQuery()==null||value.length()>4096)throw new Exception("请粘贴本机打印的智谱配对链接");
  Map<String,String> fields=new LinkedHashMap<>();
  for(String part:u.getRawQuery().split("&")){
   String[] pair=part.split("=",2);String key=URLDecoder.decode(pair[0],"UTF-8"),text=pair.length==2?URLDecoder.decode(pair[1],"UTF-8"):"";
   if(!java.util.Arrays.asList("sid","mid","name","app_version").contains(key)||fields.put(key,text)!=null)throw new Exception("配对链接参数无效");
  }
  String sid=fields.getOrDefault("sid",""),mid=fields.getOrDefault("mid",""),name=fields.getOrDefault("name","Codex Desktop");
  if(!sid.matches("[A-Za-z0-9_-]{1,160}")||!mid.matches("[A-Za-z0-9_-]{1,160}")||name.length()>80||name.matches("(?s).*[\\x00-\\x1f\\x7f].*"))throw new Exception("配对链接参数无效");
  return new ZCodePairing(sid,mid,name);
 }
}
