<font size='3'>Tunnelblick and openvpn_xorpatch</font>




---


## The openvpn\_xorpatch Controversy ##
A patch to add a "scramble" option to OpenVPN was [proposed](https://forums.openvpn.net/topic12605.html) in April, 2013. The option can be useful to avoid having OpenVPN traffic detected by monitoring or censoring mechanisms such as the Great Firewall of China. The option "scrambles" each buffer of traffic before it is sent between the OpenVPN client and server.

However, the patch is controversial: it was not accepted as an addition to OpenVPN by the OpenVPN developers. There is a long [discussion of the patch](https://forums.openvpn.net/topic12605.html) on the OpenVPN Community Support Forum. The last post is:

> We (OpenVPN developers) do not encourage people building their own versions of OpenVPN changing the wire-protocol like this, without the patch being through a proper patch review and having evaluated possible security risks related to such a change.

> And we especially discourage using such an approach when there exists a far better solution, used by the TOR community. It is called obfsproxy and can be used together with OpenVPN without needing any re-compilation of OpenVPN.

> For more information, have a look at these URLs<br>
<blockquote><a href='http://community.openvpn.net/openvpn/wiki/TrafficObfuscation'>http://community.openvpn.net/openvpn/wiki/TrafficObfuscation</a><br>
<a href='https://www.torproject.org/projects/obfsproxy.html.en'>https://www.torproject.org/projects/obfsproxy.html.en</a></blockquote>

<blockquote>To avoid confusing users further going for a possibly insecure setup , this thread will be locked now.</blockquote>

<h2>Tunnelblick's View</h2>
Regardless of the OpenVPN developers decision not to include the patch in OpenVPN, the patch is attractive because it is so easy to implement: simply apply the patch to both the OpenVPN server and the OpenVPN client and add a single, identical option to the configuration files for each. Using obfsproxy is more complicated because it involves running another, separate program on both the server and the client.<br>
<br>
Because the patch is so easy to implement, as of <a href='https://code.google.com/p/tunnelblick/source/detail?r=3274'><a href='https://code.google.com/p/tunnelblick/source/detail?r=3274'>r3274</a></a>, Tunnelblick includes a copy of OpenVPN with the patch. Tunnelblick continues to include an unpatched copy of OpenVPN, too, and that copy is used unless the patch's "scramble" option appears in the OpenVPN configuration file. So nobody who does not explicitly use the "scramble" option uses a patched version of OpenVPN.<br>
<br>
The original post proposing the patch claims that using the patch is sufficient to secure communications and that no other encryption is necessary:<br>
<blockquote>With this obfuscate option, I think that it is ok to use "cipher none", because working out the method used would take a lot of cryptoanalysis. The obfuscate option is also much easier on the CPU than any cipher options This is incase you are using ddwrt or openwrt or have a low speed cpu.<br>
However, without more detailed analysis by cryptographers, it seems best to ignore this advice. Beware of cryptographic advice from amateur cryptographers!</blockquote>

It is possible that if the "scramble" option becomes widely used, large organizations will have the ability and power to "unscramble" traffic and detect. That will probably be the case for configurations that use an identical <code>&lt;</code>xor_string<code>&gt;</code> or  <code>&lt;</code>password<code>&gt;</code> for many customers. This is another reason to continue to encrypt the VPN traffic using OpenVPN's <code>&lt;</code>cipher<code>&gt;</code> option.<br>
<br>
<h2>Tunnelblick Modifications to the Patch</h2>
As the OpenVPN developers point out, the patch has never been through a thorough review for security, coding, etc. However, the Tunnelblick developer has reviewed the patch, found some problems, and modified it in Tunnelblick to resolve those problems. The problems that were found and fixed involved insufficient parameter validation and a buffer overflow. Some defensive programming was also added to the modified version of the patch to increase its robustness.<br>
<br>
I invite anyone/everyone to review the patch and report any problems to me (either to the Tunnelblick Discussion Group or to me privately at my Gmail address, jkbullard). The patch is shown <a href='cOpenvpn_xorpatch#The_Patch_as_Modified_for_Use_in_Tunnelblick.md'>below</a>, and is located in the Tunnelblick source code (as of <a href='https://code.google.com/p/tunnelblick/source/detail?r=3274'><a href='https://code.google.com/p/tunnelblick/source/detail?r=3274'>r3274</a></a>) at<br>
<blockquote>third_party/sources/openvpn/openvpn-2.3.6txp/patches/02-tunnelblick-openvpn_xorpatch.diff<br>
(The "txp" suffix stands for "Tunnelblick xor patch".)</blockquote>

<h2>Scramble Option Syntax</h2>
Note: The "scramble" option and parameters in the server and client configuration files must match.<br>
<br>
<blockquote><pre><code>scramble &lt;xor_string&gt;<br>
scramble xormask &lt;xor_string&gt;</code></pre><br>
These optiona xor the bytes in each buffer with <code>&lt;</code>xor_string<code>&gt;</code>.<br>
<br></blockquote>

<blockquote><pre><code>scramble reverse</code></pre><br>
This option reverses order of the bytes in each buffer (except that the first byte is unchanged). So "abcde" becomes "aedcb".<br>
<br></blockquote>

<blockquote><pre><code>scramble xorptrpos</code></pre><br>
This option xors each byte of the buffer of traffic with the position in the buffer.<br>
<br></blockquote>

<blockquote><pre><code>scramble obfuscate &lt;password&gt;</code></pre><br>
This option performs several of the above steps, using <code>&lt;</code>password<code>&gt;</code> as the <code>&lt;</code>xor_string<code>&gt;</code> in one of the steps.</blockquote>

<h2>The Patch as Modified for Use in Tunnelblick</h2>
The following is the modified patch, as used in Tunnelblick as of <a href='https://code.google.com/p/tunnelblick/source/detail?r=3274"'>r3274</a>.<br>
This version of the patch is based on the most recent version of the <a href='https://github.com/clayface/openvpn_xorpatch/blob/master/openvpn_xor.patch'>patch</a> for OpenVPN 2.3.6 as of April, 2015.<br>
<br>
<pre><code>diff -u -r openvpn-2.3.6/src/openvpn/forward.c openvpn-2.3.6_/src/openvpn/forward.c<br>
--- openvpn-2.3.6/src/openvpn/forward.c	2014-11-29 10:00:35.000000000 -0500<br>
+++ openvpn-2.3.6_/src/openvpn/forward.c	2015-04-07 22:38:20.000000000 -0400<br>
@@ -674,7 +674,10 @@<br>
   status = link_socket_read (c-&gt;c2.link_socket,<br>
 			     &amp;c-&gt;c2.buf,<br>
 			     MAX_RW_SIZE_LINK (&amp;c-&gt;c2.frame),<br>
-			     &amp;c-&gt;c2.from);<br>
+			     &amp;c-&gt;c2.from,<br>
+			     c-&gt;options.ce.xormethod,<br>
+			     c-&gt;options.ce.xormask,<br>
+			     c-&gt;options.ce.xormasklen);<br>
 <br>
   if (socket_connection_reset (c-&gt;c2.link_socket, status))<br>
     {<br>
@@ -1150,7 +1153,10 @@<br>
 	    /* Send packet */<br>
 	    size = link_socket_write (c-&gt;c2.link_socket,<br>
 				      &amp;c-&gt;c2.to_link,<br>
-				      to_addr);<br>
+				      to_addr,<br>
+				      c-&gt;options.ce.xormethod,<br>
+				      c-&gt;options.ce.xormask,<br>
+				      c-&gt;options.ce.xormasklen);<br>
 <br>
 #ifdef ENABLE_SOCKS<br>
 	    /* Undo effect of prepend */<br>
diff -u -r openvpn-2.3.6/src/openvpn/options.c openvpn-2.3.6_/src/openvpn/options.c<br>
--- openvpn-2.3.6/src/openvpn/options.c	2014-11-29 10:00:35.000000000 -0500<br>
+++ openvpn-2.3.6_/src/openvpn/options.c	2015-04-09 12:56:32.000000000 -0400<br>
@@ -785,6 +785,9 @@<br>
   o-&gt;max_routes = MAX_ROUTES_DEFAULT;<br>
   o-&gt;resolve_retry_seconds = RESOLV_RETRY_INFINITE;<br>
   o-&gt;proto_force = -1;<br>
+  o-&gt;ce.xormethod = 0;<br>
+  o-&gt;ce.xormask ="\0";<br>
+  o-&gt;ce.xormasklen = 1;<br>
 #ifdef ENABLE_OCC<br>
   o-&gt;occ = true;<br>
 #endif<br>
@@ -903,6 +906,9 @@<br>
   setenv_int_i (es, "local_port", e-&gt;local_port, i);<br>
   setenv_str_i (es, "remote", e-&gt;remote, i);<br>
   setenv_int_i (es, "remote_port", e-&gt;remote_port, i);<br>
+  setenv_int_i (es, "xormethod", e-&gt;xormethod, i);<br>
+  setenv_str_i (es, "xormask", e-&gt;xormask, i);<br>
+  setenv_int_i (es, "xormasklen", e-&gt;xormasklen, i);<br>
 <br>
 #ifdef ENABLE_HTTP_PROXY<br>
   if (e-&gt;http_proxy_options)<br>
@@ -1348,6 +1354,9 @@<br>
   SHOW_INT (connect_retry_seconds);<br>
   SHOW_INT (connect_timeout);<br>
   SHOW_INT (connect_retry_max);<br>
+  SHOW_INT (xormethod);<br>
+  SHOW_STR (xormask);<br>
+  SHOW_INT (xormasklen);<br>
 <br>
 #ifdef ENABLE_HTTP_PROXY<br>
   if (o-&gt;http_proxy_options)<br>
@@ -5049,6 +5058,46 @@<br>
       options-&gt;proto_force = proto_force;<br>
       options-&gt;force_connection_list = true;<br>
     }<br>
+  else if (streq (p[0], "scramble") &amp;&amp; p[1])<br>
+    {<br>
+      VERIFY_PERMISSION (OPT_P_GENERAL|OPT_P_CONNECTION);<br>
+      if (streq (p[1], "xormask") &amp;&amp; p[2] &amp;&amp; (!p[3]))<br>
+	{<br>
+	  options-&gt;ce.xormethod = 1;<br>
+	  options-&gt;ce.xormask = p[2];<br>
+	  options-&gt;ce.xormasklen = strlen(options-&gt;ce.xormask);<br>
+	}<br>
+      else if (streq (p[1], "xorptrpos") &amp;&amp; (!p[2]))<br>
+	{<br>
+	  options-&gt;ce.xormethod = 2;<br>
+	  options-&gt;ce.xormask = NULL;<br>
+	  options-&gt;ce.xormasklen = 0;<br>
+	}<br>
+      else if (streq (p[1], "reverse") &amp;&amp; (!p[2]))<br>
+	{<br>
+	  options-&gt;ce.xormethod = 3;<br>
+	  options-&gt;ce.xormask = NULL;<br>
+	  options-&gt;ce.xormasklen = 0;<br>
+	}<br>
+      else if (streq (p[1], "obfuscate") &amp;&amp; p[2] &amp;&amp; (!p[3]))<br>
+	{<br>
+	  options-&gt;ce.xormethod = 4;<br>
+	  options-&gt;ce.xormask = p[2];<br>
+	  options-&gt;ce.xormasklen = strlen(options-&gt;ce.xormask);<br>
+	}<br>
+      else if (!p[2])<br>
+	{<br>
+	  msg (M_WARN, "WARNING: No recognized 'scramble' method specified; using 'scramble xormask \"%s\"'", p[1]);<br>
+	  options-&gt;ce.xormethod = 1;<br>
+	  options-&gt;ce.xormask = p[1];<br>
+	  options-&gt;ce.xormasklen = strlen(options-&gt;ce.xormask);<br>
+	}<br>
+      else<br>
+	{<br>
+	  msg (msglevel, "No recognized 'scramble' method specified or extra parameters for 'scramble'");<br>
+	  goto err;<br>
+	}<br>
+    }<br>
 #ifdef ENABLE_HTTP_PROXY<br>
   else if (streq (p[0], "http-proxy") &amp;&amp; p[1])<br>
     {<br>
diff -u -r openvpn-2.3.6/src/openvpn/options.h openvpn-2.3.6_/src/openvpn/options.h<br>
--- openvpn-2.3.6/src/openvpn/options.h	2014-11-29 10:00:35.000000000 -0500<br>
+++ openvpn-2.3.6_/src/openvpn/options.h	2015-04-07 22:38:20.000000000 -0400<br>
@@ -100,6 +100,9 @@<br>
   int connect_retry_max;<br>
   int connect_timeout;<br>
   bool connect_timeout_defined;<br>
+  int xormethod;<br>
+  const char *xormask;<br>
+  int xormasklen;<br>
 #ifdef ENABLE_HTTP_PROXY<br>
   struct http_proxy_options *http_proxy_options;<br>
 #endif  <br>
diff -u -r openvpn-2.3.6/src/openvpn/socket.c openvpn-2.3.6_/src/openvpn/socket.c<br>
--- openvpn-2.3.6/src/openvpn/socket.c	2014-11-29 10:00:35.000000000 -0500<br>
+++ openvpn-2.3.6_/src/openvpn/socket.c	2015-04-09 08:48:01.000000000 -0400<br>
@@ -52,6 +52,51 @@<br>
   IPv6_TCP_HEADER_SIZE,<br>
 };<br>
 <br>
+int buffer_mask (struct buffer *buf, const char *mask, int xormasklen) {<br>
+	int i;<br>
+	uint8_t *b;<br>
+	for (i = 0, b = BPTR (buf); i &lt; BLEN(buf); i++, b++) {<br>
+		*b = *b ^ mask[i % xormasklen];<br>
+	}<br>
+	return BLEN (buf);<br>
+}<br>
+<br>
+int buffer_xorptrpos (struct buffer *buf) {<br>
+	int i;<br>
+	uint8_t *b;<br>
+	for (i = 0, b = BPTR (buf); i &lt; BLEN(buf); i++, b++) {<br>
+		*b = *b ^ i+1;<br>
+	}<br>
+	return BLEN (buf);<br>
+}<br>
+<br>
+int buffer_reverse (struct buffer *buf) {<br>
+/* This function has been rewritten for Tunnelblick. The buffer_reverse function at<br>
+ * https://github.com/clayface/openvpn_xorpatch<br>
+ * makes a copy of the buffer and it writes to the byte **after** the<br>
+ * buffer contents, so if the buffer is full then it writes outside of the buffer.<br>
+ * This rewritten version does neither.<br>
+ *<br>
+ * For interoperability, this rewritten version preserves the behavior of the original<br>
+ * function: it does not modify the first character of the buffer. So it does not<br>
+ * actually reverse the contents of the buffer. Instead, it changes 'abcde' to 'aedcb'.<br>
+ * (Of course, the actual buffer contents are bytes, and not necessarily characters.)<br>
+ */<br>
+  int len = BLEN(buf);<br>
+  if (  len &gt; 2  ) {                           /* Leave '', 'a', and 'ab' alone */<br>
+    int i;<br>
+    uint8_t *b_start = BPTR (buf) + 1;	        /* point to first byte to swap */<br>
+    uint8_t *b_end   = BPTR (buf) + (len - 1); /* point to last byte to swap */<br>
+    uint8_t tmp;<br>
+    for (i = 0; i &lt; (len-1)/2; i++, b_start++, b_end--) {<br>
+      tmp = *b_start;<br>
+      *b_start = *b_end;<br>
+      *b_end = tmp;<br>
+    }<br>
+  }<br>
+  return len;<br>
+}<br>
+<br>
 /*<br>
  * Convert sockflags/getaddr_flags into getaddr_flags<br>
  */<br>
diff -u -r openvpn-2.3.6/src/openvpn/socket.h openvpn-2.3.6_/src/openvpn/socket.h<br>
--- openvpn-2.3.6/src/openvpn/socket.h	2014-11-29 10:00:35.000000000 -0500<br>
+++ openvpn-2.3.6_/src/openvpn/socket.h	2015-04-08 20:12:02.000000000 -0400<br>
@@ -250,6 +250,10 @@<br>
 #endif<br>
 };<br>
 <br>
+int buffer_mask (struct buffer *buf, const char *xormask, int xormasklen);<br>
+int buffer_xorptrpos (struct buffer *buf);<br>
+int buffer_reverse (struct buffer *buf);<br>
+<br>
 /*<br>
  * Some Posix/Win32 differences.<br>
  */<br>
@@ -875,30 +879,56 @@<br>
 link_socket_read (struct link_socket *sock,<br>
 		  struct buffer *buf,<br>
 		  int maxsize,<br>
-		  struct link_socket_actual *from)<br>
+		  struct link_socket_actual *from,<br>
+		  int xormethod,<br>
+		  const char *xormask,<br>
+		  int xormasklen)<br>
 {<br>
+  int res;<br>
   if (proto_is_udp(sock-&gt;info.proto)) /* unified UDPv4 and UDPv6 */<br>
     {<br>
-      int res;<br>
 <br>
 #ifdef WIN32<br>
       res = link_socket_read_udp_win32 (sock, buf, from);<br>
 #else<br>
       res = link_socket_read_udp_posix (sock, buf, maxsize, from);<br>
 #endif<br>
-      return res;<br>
     }<br>
   else if (proto_is_tcp(sock-&gt;info.proto)) /* unified TCPv4 and TCPv6 */<br>
     {<br>
       /* from address was returned by accept */<br>
       addr_copy_sa(&amp;from-&gt;dest, &amp;sock-&gt;info.lsa-&gt;actual.dest);<br>
-      return link_socket_read_tcp (sock, buf);<br>
+      res = link_socket_read_tcp (sock, buf);<br>
     }<br>
   else<br>
     {<br>
       ASSERT (0);<br>
       return -1; /* NOTREACHED */<br>
     }<br>
+  switch(xormethod)<br>
+    {<br>
+      case 0:<br>
+       break;<br>
+      case 1:<br>
+       buffer_mask(buf,xormask,xormasklen);<br>
+       break;<br>
+      case 2:<br>
+       buffer_xorptrpos(buf);<br>
+       break;<br>
+      case 3:<br>
+       buffer_reverse(buf);<br>
+       break;<br>
+      case 4:<br>
+       buffer_mask(buf,xormask,xormasklen);<br>
+       buffer_xorptrpos(buf);<br>
+       buffer_reverse(buf);<br>
+       buffer_xorptrpos(buf);<br>
+       break;<br>
+      default:<br>
+       ASSERT (0);<br>
+       return -1; /* NOTREACHED */<br>
+    }<br>
+  return res;<br>
 }<br>
 <br>
 /*<br>
@@ -982,8 +1012,34 @@<br>
 static inline int<br>
 link_socket_write (struct link_socket *sock,<br>
 		   struct buffer *buf,<br>
-		   struct link_socket_actual *to)<br>
+		   struct link_socket_actual *to,<br>
+		   int xormethod,<br>
+		   const char *xormask,<br>
+		   int xormasklen)<br>
 {<br>
+  switch(xormethod)<br>
+    {<br>
+      case 0:<br>
+       break;<br>
+      case 1:<br>
+       buffer_mask(buf,xormask,xormasklen);<br>
+       break;<br>
+      case 2:<br>
+       buffer_xorptrpos(buf);<br>
+       break;<br>
+      case 3:<br>
+       buffer_reverse(buf);<br>
+       break;<br>
+      case 4:<br>
+       buffer_xorptrpos(buf);<br>
+       buffer_reverse(buf);<br>
+       buffer_xorptrpos(buf);<br>
+       buffer_mask(buf,xormask,xormasklen);<br>
+       break;<br>
+      default:<br>
+       ASSERT (0);<br>
+       return -1; /* NOTREACHED */<br>
+    }<br>
   if (proto_is_udp(sock-&gt;info.proto)) /* unified UDPv4 and UDPv6 */<br>
     {<br>
       return link_socket_write_udp (sock, buf, to);<br>
</code></pre>

<hr />

<h3>PLEASE USE THE <a href='http://groups.google.com/group/tunnelblick-discuss'>TUNNELBLICK DISCUSSION GROUP</a> FOR COMMENTS OR QUESTIONS</h3>