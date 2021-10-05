---
layout: page
current: archive
title: All Tags
navigation: true
logo: 
class: page-template
subclass: 'post page'
---

<div id="post-index" class="well article">
{% capture site_tags %}{% for tag in site.tags %}{{ tag | first }}{% unless forloop.last %},{% endunless %}{% endfor %}{% endcapture %}
{% assign tags_list = site_tags | split:',' | sort %}

<ul class="entry-meta inline-list">
  {% for item in (0..site.tags.size) %}{% unless forloop.last %}
    {% capture this_word %}{{ tags_list[item] | strip_newlines }}{% endcapture %}
  	<li><a href="#{{ this_word }}" class="tag"><span class="term alltags">{{ this_word }}</span> <span class="count alltags">{{ site.tags[this_word].size }}</span></a></li>
  {% endunless %}{% endfor %}
</ul>

{% for item in (0..site.tags.size) %}{% unless forloop.last %}
  {% capture this_word %}{{ tags_list[item] | strip_newlines }}{% endcapture %}
	<article>
	<h2 id="{{ this_word }}" class="tag-heading">{{ this_word | upcase }}</h2>
		<ul>
    {% for post in site.tags[this_word] %}{% if post.title != null %}
      <!-- <li class="entry-title"><a href="{{ site.url }}{{ post.url }}" target="_blank" title="{{ post.title }}">{{ post.title }}</a></li> -->
      <li class="entry-title"><a href="{{ post.url }}" target="_blank" title="{{ post.title }}">{{ post.title }}</a></li>
    {% endif %}{% endfor %}
		</ul>
	</article><!-- /.hentry -->
{% endunless %}{% endfor %}
</div>