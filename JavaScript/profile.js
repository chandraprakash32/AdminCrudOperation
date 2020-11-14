% extends "layout.html" %}
{% from "_form_macros.html" import render_field %}
 
{% block content %}
 
<div class="user-profile">
  <div class="page-header">
    <h2>User Profile</h2>
  </div>
 
  <div class="row">
    <div class="col-sm-6">
      <div class="panel panel-primary">
        <div class="panel-heading">Email Address</div>
        <div class="panel-body">{{current_user.email}}</div>
      </div>
 
      <div class="panel panel-info">
        <div class="panel-heading">Account Actions</div>
        <div class="panel-body"><a href="#">Change Email</a></div>
        <div class="panel-body"><a href="#">Change Password</a></div>
        {% if not current_user.email_confirmed %}
          <div class="panel-body"><a href="#">Resend Email Confirmation</a></div>
        {% endif %}
      </div>
 
      <div class="panel panel-info">
        <div class="panel-heading">Statistics</div>
        <div class="panel-body">Member since: {{ current_user.registered_on.strftime("%A %B %d, %Y") }}</div>
        {% if current_user.last_logged_in != None %}
          <div class="panel-body">Last Logged In: {{ current_user.last_logged_in.strftime("%A %B %d, %Y") }}</div>
        {% else %}
          <div class="panel-body">First time logged in. Welcome!</div>
        {% endif %}
        {% if current_user.email_confirmed %}
          <div class="panel-body">Email confirmed on: {{ current_user.email_confirmed_on.strftime("%A %B %d, %Y") }}</div>
        {% else %}
          <div class="panel-body">Email has not been confirmed!</div>
        {% endif %}
      </div>
    </div>
  </div>
</div>
 
{% endblock %}