(function() {var type_impls = {
"svsm":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-FixedString%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/svsm/string.rs.html#11\">source</a><a href=\"#impl-Clone-for-FixedString%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;const T: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"svsm/string/struct.FixedString.html\" title=\"struct svsm::string::FixedString\">FixedString</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/svsm/string.rs.html#11\">source</a><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.81.0/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; <a class=\"struct\" href=\"svsm/string/struct.FixedString.html\" title=\"struct svsm::string::FixedString\">FixedString</a>&lt;T&gt;</h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/1.81.0/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.81.0/src/core/clone.rs.html#172\">source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.81.0/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/core/primitive.reference.html\">&amp;Self</a>)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/1.81.0/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","svsm::fs::api::FileName"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Debug-for-FixedString%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/svsm/string.rs.html#11\">source</a><a href=\"#impl-Debug-for-FixedString%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;const T: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> for <a class=\"struct\" href=\"svsm/string/struct.FixedString.html\" title=\"struct svsm::string::FixedString\">FixedString</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/svsm/string.rs.html#11\">source</a><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.81.0/core/fmt/trait.Debug.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/1.81.0/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"type\" href=\"https://doc.rust-lang.org/1.81.0/core/fmt/type.Result.html\" title=\"type core::fmt::Result\">Result</a></h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/1.81.0/core/fmt/trait.Debug.html#tymethod.fmt\">Read more</a></div></details></div></details>","Debug","svsm::fs::api::FileName"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Default-for-FixedString%3CN%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/svsm/string.rs.html#41-45\">source</a><a href=\"#impl-Default-for-FixedString%3CN%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/string/struct.FixedString.html\" title=\"struct svsm::string::FixedString\">FixedString</a>&lt;N&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.default\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/svsm/string.rs.html#42-44\">source</a><a href=\"#method.default\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.81.0/core/default/trait.Default.html#tymethod.default\" class=\"fn\">default</a>() -&gt; Self</h4></section></summary><div class='docblock'>Returns the “default value” for a type. <a href=\"https://doc.rust-lang.org/1.81.0/core/default/trait.Default.html#tymethod.default\">Read more</a></div></details></div></details>","Default","svsm::fs::api::FileName"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Display-for-FixedString%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/svsm/string.rs.html#104-111\">source</a><a href=\"#impl-Display-for-FixedString%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;const T: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/fmt/trait.Display.html\" title=\"trait core::fmt::Display\">Display</a> for <a class=\"struct\" href=\"svsm/string/struct.FixedString.html\" title=\"struct svsm::string::FixedString\">FixedString</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/svsm/string.rs.html#105-110\">source</a><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.81.0/core/fmt/trait.Display.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/1.81.0/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"type\" href=\"https://doc.rust-lang.org/1.81.0/core/fmt/type.Result.html\" title=\"type core::fmt::Result\">Result</a></h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/1.81.0/core/fmt/trait.Display.html#tymethod.fmt\">Read more</a></div></details></div></details>","Display","svsm::fs::api::FileName"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-FixedString%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/svsm/string.rs.html#17-39\">source</a><a href=\"#impl-FixedString%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;const T: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"struct\" href=\"svsm/string/struct.FixedString.html\" title=\"struct svsm::string::FixedString\">FixedString</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><section id=\"method.new\" class=\"method\"><a class=\"src rightside\" href=\"src/svsm/string.rs.html#18-23\">source</a><h4 class=\"code-header\">pub const fn <a href=\"svsm/string/struct.FixedString.html#tymethod.new\" class=\"fn\">new</a>() -&gt; Self</h4></section><section id=\"method.push\" class=\"method\"><a class=\"src rightside\" href=\"src/svsm/string.rs.html#25-34\">source</a><h4 class=\"code-header\">pub fn <a href=\"svsm/string/struct.FixedString.html#tymethod.push\" class=\"fn\">push</a>(&amp;mut self, c: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/core/primitive.char.html\">char</a>)</h4></section><section id=\"method.length\" class=\"method\"><a class=\"src rightside\" href=\"src/svsm/string.rs.html#36-38\">source</a><h4 class=\"code-header\">pub fn <a href=\"svsm/string/struct.FixedString.html#tymethod.length\" class=\"fn\">length</a>(&amp;self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/core/primitive.usize.html\">usize</a></h4></section></div></details>",0,"svsm::fs::api::FileName"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-From%3C%26str%3E-for-FixedString%3CN%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/svsm/string.rs.html#65-74\">source</a><a href=\"#impl-From%3C%26str%3E-for-FixedString%3CN%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/core/primitive.str.html\">str</a>&gt; for <a class=\"struct\" href=\"svsm/string/struct.FixedString.html\" title=\"struct svsm::string::FixedString\">FixedString</a>&lt;N&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.from\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/svsm/string.rs.html#66-73\">source</a><a href=\"#method.from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html#tymethod.from\" class=\"fn\">from</a>(st: &amp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/core/primitive.str.html\">str</a>) -&gt; <a class=\"struct\" href=\"svsm/string/struct.FixedString.html\" title=\"struct svsm::string::FixedString\">FixedString</a>&lt;N&gt;</h4></section></summary><div class='docblock'>Converts to this type from the input type.</div></details></div></details>","From<&str>","svsm::fs::api::FileName"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-From%3C%5Bu8;+N%5D%3E-for-FixedString%3CN%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/svsm/string.rs.html#47-63\">source</a><a href=\"#impl-From%3C%5Bu8;+N%5D%3E-for-FixedString%3CN%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/core/primitive.u8.html\">u8</a>; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/core/primitive.array.html\">N</a>]&gt; for <a class=\"struct\" href=\"svsm/string/struct.FixedString.html\" title=\"struct svsm::string::FixedString\">FixedString</a>&lt;N&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.from\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/svsm/string.rs.html#48-62\">source</a><a href=\"#method.from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.81.0/core/convert/trait.From.html#tymethod.from\" class=\"fn\">from</a>(arr: [<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/core/primitive.u8.html\">u8</a>; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/core/primitive.array.html\">N</a>]) -&gt; <a class=\"struct\" href=\"svsm/string/struct.FixedString.html\" title=\"struct svsm::string::FixedString\">FixedString</a>&lt;N&gt;</h4></section></summary><div class='docblock'>Converts to this type from the input type.</div></details></div></details>","From<[u8; N]>","svsm::fs::api::FileName"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PartialEq%3C%26str%3E-for-FixedString%3CN%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/svsm/string.rs.html#76-88\">source</a><a href=\"#impl-PartialEq%3C%26str%3E-for-FixedString%3CN%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a>&lt;&amp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/core/primitive.str.html\">str</a>&gt; for <a class=\"struct\" href=\"svsm/string/struct.FixedString.html\" title=\"struct svsm::string::FixedString\">FixedString</a>&lt;N&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.eq\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/svsm/string.rs.html#77-87\">source</a><a href=\"#method.eq\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.81.0/core/cmp/trait.PartialEq.html#tymethod.eq\" class=\"fn\">eq</a>(&amp;self, other: &amp;&amp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/core/primitive.str.html\">str</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/core/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>self</code> and <code>other</code> values to be equal, and is used\nby <code>==</code>.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ne\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.81.0/src/core/cmp.rs.html#262\">source</a></span><a href=\"#method.ne\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.81.0/core/cmp/trait.PartialEq.html#method.ne\" class=\"fn\">ne</a>(&amp;self, other: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/core/primitive.reference.html\">&amp;Rhs</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/core/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>!=</code>. The default implementation is almost always\nsufficient, and should not be overridden without very good reason.</div></details></div></details>","PartialEq<&str>","svsm::fs::api::FileName"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PartialEq-for-FixedString%3CN%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/svsm/string.rs.html#90-102\">source</a><a href=\"#impl-PartialEq-for-FixedString%3CN%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a> for <a class=\"struct\" href=\"svsm/string/struct.FixedString.html\" title=\"struct svsm::string::FixedString\">FixedString</a>&lt;N&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.eq\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/svsm/string.rs.html#91-101\">source</a><a href=\"#method.eq\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.81.0/core/cmp/trait.PartialEq.html#tymethod.eq\" class=\"fn\">eq</a>(&amp;self, other: &amp;<a class=\"struct\" href=\"svsm/string/struct.FixedString.html\" title=\"struct svsm::string::FixedString\">FixedString</a>&lt;N&gt;) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/core/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>self</code> and <code>other</code> values to be equal, and is used\nby <code>==</code>.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ne\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.81.0/src/core/cmp.rs.html#262\">source</a></span><a href=\"#method.ne\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.81.0/core/cmp/trait.PartialEq.html#method.ne\" class=\"fn\">ne</a>(&amp;self, other: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/core/primitive.reference.html\">&amp;Rhs</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/core/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>!=</code>. The default implementation is almost always\nsufficient, and should not be overridden without very good reason.</div></details></div></details>","PartialEq","svsm::fs::api::FileName"],["<section id=\"impl-Copy-for-FixedString%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/svsm/string.rs.html#11\">source</a><a href=\"#impl-Copy-for-FixedString%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;const T: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.81.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.81.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> for <a class=\"struct\" href=\"svsm/string/struct.FixedString.html\" title=\"struct svsm::string::FixedString\">FixedString</a>&lt;T&gt;</h3></section>","Copy","svsm::fs::api::FileName"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()