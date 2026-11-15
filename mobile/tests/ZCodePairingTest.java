package io.github.try2love.codexbridge;

public final class ZCodePairingTest {
 public static void main(String[] args)throws Exception {
  String base="https://zcode.z.ai/remote/v4?sid=d_test&mid=codex-desktop-test";
  ZCodePairing parsed=ZCodePairing.parse(base+"&name=AK-NEW+Codex&app_version=3.18.2");
  if(!parsed.sid.equals("d_test")||!parsed.mid.equals("codex-desktop-test")||!parsed.name.equals("AK-NEW Codex"))throw new AssertionError("pairing identity");
  String[] invalid={base+"&mid=second",base+"&%73id=second",base+"&token=secret",base+"#token",base.replace("https:","http:"),base.replace("zcode.z.ai/","zcode.z.ai.evil/"),base.replace("zcode.z.ai/","user@zcode.z.ai/"),base.replace("zcode.z.ai/","zcode.z.ai:443/"),base.replace("d_test",""),base+"&name=%0a"};
  for(String value:invalid){boolean failed=false;try{ZCodePairing.parse(value);}catch(Exception expected){failed=true;}if(!failed)throw new AssertionError("accepted invalid pairing");}
  System.out.println("ZCODE_PAIRING_PASS 11");
 }
}
