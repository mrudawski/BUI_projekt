import scheduler_project.settings
from .forms import CreateUserForm, UserFullnameChoiceField
from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from .forms import CreateUserForm
from .forms import CreateEvent
from .forms import SubjectForm, AddComment
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from datetime import datetime, date
from django.contrib.auth.models import Group
from .decorators import unauthenticated_user, allowed_users
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect
from .models import Event, Subject, User, Comment, Polls, Dates
from django.core.mail import send_mail, get_connection, send_mass_mail
from django.core.mail import EmailMessage
from django.utils import timezone
import pytz
from django.shortcuts import get_object_or_404
from django.core.paginator import Paginator, EmptyPage
from django.template.loader import get_template, render_to_string
import os
from .forms import ChangePassword
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.contrib.auth.forms import PasswordResetForm
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from django.conf import settings
from django.http import HttpResponse
from django.db.models import Q
from django.core.mail import BadHeaderError, send_mail
from django.template import loader
from collections import Counter
from Crypto.Cipher import DES
from django.contrib.messages import get_messages


def home_page(request):
    now = timezone.now()
    upcoming_events_list = Event.objects.filter(planning_date__gte=now)

    context = {'upcoming_events_list': upcoming_events_list}

    return render(request, 'schedule/home.html', context)


def login_page(request):
    if request.user.is_authenticated:
        return redirect('home')
    if request.method == 'POST':
        username = request.POST.get('username')  # html name="username"
        password = request.POST.get('password')
        remember_me = request.POST.get('remember_me')

        if not remember_me:
            request.session.set_expiry(0)

        user = authenticate(request, username=username, password=password)

        # Sprawdzanie parametru next, by móc przekierować niezalogowanego użytkownika
        # w miejsce do którego chciał się dostać po poprawnym logowaniu
        if user is not None:
            login(request, user)
            if 'next' in request.POST:

                if not remember_me:
                    request.session.set_expiry(0)

                return redirect(request.POST.get('next'))
            else:
                return redirect('home')
        else:
            messages.info(request, 'Nazwa użytkownika lub hasło są nieprawidłowe')

    context = {}
    return render(request, 'schedule/login.html', context)


@unauthenticated_user
def register_page(request):
    if request.method == 'POST':
        form = CreateUserForm(request.POST)
        if form.is_valid():

            user = form.save()
            username = form.cleaned_data.get('username')
            raw_password = form.cleaned_data.get('password1')
            group = Group.objects.get(name='employee')
            user.groups.add(group)
            user = authenticate(username=username, password=raw_password)
            login(request, user)
            return redirect('home')

    else:
        form = CreateUserForm()

    context = {'form': form}
    return render(request, 'schedule/register.html', context)


def events_list(request):

    today = datetime.today()
    User = get_user_model()
    fullnames = User.objects.all()

    all_events_list = Event.objects.all()

    sort_by = request.GET.get('sort_by')

    show = request.GET.get('show')
    only_mine = request.GET.get('only_mine')
    drafts = request.GET.get('drafts')

    organizer = request.GET.get('organizer')
    title = request.GET.get('title')

    if show == "historical":
        all_events_list = all_events_list.filter(planning_date__lte=today)

    else:
        all_events_list = all_events_list.filter(planning_date__gte=today)

    if drafts:
        all_events_list = all_events_list.filter(status='draft')
    else:
        all_events_list = all_events_list.filter(status='publish')

    if request.user.is_authenticated and request.user.groups.all()[0].name != 'admin' and drafts:
        all_events_list = all_events_list.filter(organizer=request.user)

    if organizer:
        all_events_list = all_events_list.filter(organizer=organizer)

    if only_mine:
        all_events_list = all_events_list.filter(organizer=request.user)

    if title and title != '':
        all_events_list = all_events_list.filter(title__icontains=title)

    if not request.user.is_authenticated:
        all_events_list = all_events_list.filter(status='publish')

    # SORTOWANIE

    if sort_by == 'latest':
        all_events_list = all_events_list.order_by('planning_date')

    elif sort_by == 'oldest':
        all_events_list = all_events_list.order_by('-planning_date')

    elif sort_by == 'alphabetical':
        all_events_list = all_events_list.order_by('title')

    else:
        all_events_list = all_events_list.all()

    # FILTROWANIE







    pa = Paginator(all_events_list, 12)

    page_num = request.GET.get('page', 1)
    try:
        page = pa.page(page_num)
    except EmptyPage:
        page = pa.page(1)

    # wyswietalnie informacji o dodaniu szkolenia/szkicu
    try:
        request.session['ref_times'] += 1
        if request.session.get('ref_times') == 2:
            if request.session.get('event_success') is True:
                event_success = True
                request.session['event_success'] = False
                context = {'list': page, 'fullnames': fullnames, 'event_success': event_success}
                return render(request, 'schedule/events_list.html', context)

            if request.session.get('draft_success') is True:
                draft_success = True
                request.session['draft_success'] = False
                context = {'list': page, 'fullnames': fullnames, 'draft_success': draft_success}
                return render(request, 'schedule/events_list.html', context)
    except:
        pass

    context = {'list': page, 'fullnames': fullnames}

    return render(request, 'schedule/events_list.html', context)

@allowed_users(allowed_roles=['admin'])
def create_event(request):
    User = get_user_model()
    fullnames = User.objects.all()
    if request.method == 'POST':
        form = CreateEvent(request.POST, request.FILES)
        if form.is_valid():
            organizer = form.cleaned_data.get('organizer')
            event_form = form.save()
            event_pk = event_form.pk
            organizer_pk = get_object_or_404(User, username=organizer).pk
            request.session['ref_times'] = 0
            request.session['event_success'] = True
            return redirect('events_list')

    else:
        form = CreateEvent()
    form = CreateEvent()
    context = {'form': form, 'fullnames': fullnames}

    return render(request, 'schedule/create_event.html', context)

@login_required(login_url='login')
def logout_user(request):
    logout(request)
    return redirect('home')


def about(request):
    return render(request, 'schedule/about.html')


def user_page(request):
    context = {}
    return render(request, 'schedule/user.html', context)

@allowed_users(allowed_roles=['admin'])
def users_list(request):
    if request.method == 'POST':
        delete_id = request.POST.get('delete')
        user = get_user_model()
        selected_user = user.objects.filter(id=delete_id)
        selected_user.delete()

    user = get_user_model()
    users = user.objects.all()

    lead_cnt = []
    subjects_cnt = []

    for i in users:
        lead_cnt.append(Event.objects.filter(organizer=i.id).count())
        subjects_cnt.append(Subject.objects.filter(proposer=i.id).count())

    context = {'users': users, 'lead_cnt': lead_cnt, 'subjects_cnt': subjects_cnt}

    return render(request, 'schedule/users_list.html', context)


@allowed_users(allowed_roles=['admin'])
def user_details(request, index):
    if request.method == 'GET':
        user = get_user_model()
        selected_user = user.objects.filter(id=index)

        subjects = Subject.objects.filter(proposer=index)
        events = Event.objects.filter(organizer=index)

        subjects_cnt = subjects.count()
        events_cnt = events.count()

        context = {'selected_user': selected_user, 'subjects': subjects, 'events': events, 'subjects_cnt': subjects_cnt, 'events_cnt': events_cnt}
        return render(request, 'schedule/user_details.html', context)


@allowed_users(allowed_roles=['admin'])
def user_edit(request, index):


    if request.method == 'GET':
        user = get_user_model()
        selected_user = user.objects.filter(id=index)
        context = {'selected_user': selected_user}

    if request.method == 'POST':
        user = get_user_model()
        selected_user = user.objects.filter(id=index)

        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        username = request.POST.get('username')
        email = request.POST.get('email')
        if_admin = request.POST.get('if_admin')

        if if_admin:
            employee_group = Group.objects.get(name='employee')
            admin_group = Group.objects.get(name='admin')
            employee_group.user_set.remove(index)
            admin_group.user_set.add(index)
        else:
            employee_group = Group.objects.get(name='employee')
            admin_group = Group.objects.get(name='admin')
            admin_group.user_set.remove(index)
            employee_group.user_set.add(index)

        update_user = user.objects.filter(id=index).update(first_name=first_name, last_name=last_name, username=username, email=email)

        return redirect('users_list')

    return render(request, 'schedule/user_edit.html', context)


@allowed_users(allowed_roles=['admin'])
def delete_user(request, index):
    try:
        user = get_user_model()
        selected_user = user.objects.filter(id=index)
        selected_user.delete()
        return redirect('users_list')

    except:
        return redirect('users_list')

    return render(request, 'schedule/users_list.html')

@allowed_users(allowed_roles=['admin', 'employee'])
def event_edit(request, index):
    poll_status = 0
    if request.user.groups.all()[0].name == 'admin':

        if request.method == 'GET':
            event = Event.objects.filter(id=index)
            user = get_user_model()
            users = user.objects.all()

            context = {'event': event, 'users': users, 'permitted': True,}
            return render(request, 'schedule/event_edit.html', context)

        if request.method == 'POST':

            selected_event = Event.objects.get(id=index)

            title = request.POST.get('title')
            description = request.POST.get('description')
            organizer = request.POST.get('organizer')
            planning_date = request.POST.get('planning_date')
            duration = request.POST.get('duration')
            link = request.POST.get('link')

            Event.objects.filter(id=index).update(title=title, description=description, organizer=organizer, planning_date=planning_date, duration=duration, link=link)

            new_icon = request.FILES.get('icon')
            new_attachment = request.FILES.get('attachment')

            if new_icon:
                selected_event.icon = new_icon
                selected_event.save(update_fields=["icon"])

            if new_attachment:
                selected_event.attachment = new_attachment
                selected_event.save(update_fields=["attachment"])

            return redirect('events_list')

        return render(request, 'schedule/event_edit.html', context)

    elif request.user.groups.all()[0].name == 'employee':

        try:
            event = Event.objects.filter(id=index)
        except:
            context = {'not_permitted': True}
            return render(request, 'schedule/event_edit.html', context)

        if event[0].planning_date < datetime.today():
            past = True
        else:
            past = False

        for i in event:

            if i.organizer == request.user:

                if request.method == 'GET':
                    event = Event.objects.filter(id=index)
                    user = get_user_model()

                    if event[0].planning_date < datetime.today():
                        past = True
                    else:
                        past = False

                    poll = 0
                    dates = 0
                    total_votes = 0
                    poll_in_progress = False
                    poll_exist = False
                    try:
                        poll = Polls.objects.get(event=index)
                    except:
                        poll = 0

                    if poll:
                        poll_exist = True
                        # w trakcie
                        poll_status = ''
                        if poll.since_active <= date.today() < poll.till_active:
                            poll_status = 'in_progress'
                            # poll_in_progress = True
                        # else:
                        #     poll_in_progress = False
                        # zakonczona
                        elif poll.till_active < date.today():
                            # poll_ended = True
                            poll_status = 'ended'
                        # nierozpoczeta
                        elif poll.since_active > date.today():
                            # poll_not_started = True
                            poll_status = 'not_started'
                        dates = Dates.objects.filter(poll=poll).order_by('date')
                        total_votes = 0
                        if_voted = False
                        # sprawdzam czy user juz zaglosowal na ktorykolwiek z terminow
                        for el in dates:
                            if el.users.filter(id=request.user.id).exists():
                                if_voted = True
                            total_votes += el.count

                        if total_votes == 0:
                            total_votes = -1
                    context = {'event': event, 'past': past, 'poll': poll,
                               'dates': dates,
                               'poll_in_progress': poll_in_progress, 'poll_exist': poll_exist,
                               'poll_status': poll_status, 'total_votes': total_votes}
                    return render(request, 'schedule/event_edit.html', context)
                    # context = {'event': event, 'past': past}
                    # return render(request, 'schedule/event_edit.html', context)

                if request.method == 'POST':

                    selected_event = Event.objects.get(id=index)

                    description = request.POST.get('description')
                    planning_date = request.POST.get('planning_date')
                    duration = request.POST.get('duration')
                    link = request.POST.get('link')

                    Event.objects.filter(id=index).update(description=description, planning_date=planning_date, duration=duration, link=link)

                    new_icon = request.FILES.get('icon')
                    new_attachment = request.FILES.get('attachment')

                    if new_icon:
                        selected_event.icon = new_icon
                        selected_event.save(update_fields=["icon"])

                    if new_attachment:
                        selected_event.attachment = new_attachment
                        selected_event.save(update_fields=["attachment"])

                    return redirect('events_list')

            else:
                context = {'not_permitted': True}
                return render(request, 'schedule/event_edit.html', context)


@allowed_users(allowed_roles=['admin'])
def delete_event(request, index):
    try:
        selected_event = Event.objects.filter(id=index)
        selected_event.delete()

        return redirect('events_list')

    except:
        return redirect('events_list')


@allowed_users(allowed_roles=['admin', 'employee'])
def my_profile(request):

    my_events = Event.objects.filter(organizer=request.user)
    my_subjects = Subject.objects.filter(proposer=request.user)

    events_cnt = my_events.count()
    subjects_cnt = my_subjects.count()

    if request.method == 'POST' and request.POST.get('change_profile') == '1':

        user = get_user_model()

        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')

        update_user = user.objects.filter(id=request.user.id).update(first_name=first_name, last_name=last_name, email=email)

        return redirect('my_profile')

    elif request.method == 'POST':
        form = ChangePassword(user=request.user, data=request.POST)
        if form.is_valid():
            form.save()
            login(request, request.user)
            messages.success(request, 'Hasło zostało zmienione.')
            return redirect('my_profile')
    else:
        form = ChangePassword(user=request.user)

    for field in form.fields.values():
        field.help_text = None

    context = {'my_events': my_events, 'my_subjects': my_subjects, 'events_cnt': events_cnt, 'subjects_cnt': subjects_cnt, 'form': form }

    return render(request, 'schedule/my_profile.html', context)


#@allowed_users(allowed_roles=['admin', 'employee'])
def event_details(request, index):

    if request.method == 'GET':
        selected_event = Event.objects.filter(id=index)
        comments = Comment.objects.filter(event=index)
        comments_cnt = comments.count()
        form = AddComment()
        poll = 0
        poll_exist = False
        try:
            poll = Polls.objects.get(event=index)
        except:
            pass

        if poll:
            poll_exist = True
            # w trakcie
            poll_status = ''
            if poll.since_active is None or poll.till_active is None:
                poll_status = 'not_set'
            elif poll.since_active <= date.today() <= poll.till_active:
                poll_status = 'in_progress'
            # zakonczona
            elif poll.till_active < date.today():
                poll_status = 'ended'
            # nierozpoczeta
            elif poll.since_active > date.today():
                poll_status = 'not_started'
            dates = Dates.objects.filter(poll=poll).order_by('date')
            total_votes = 0
            if_voted = False
            # sprawdzam czy user juz zaglosowal na ktorykolwiek z terminow
            for el in dates:
                if el.users.filter(id=request.user.id).exists():
                    if_voted = True
                total_votes += el.count

            if total_votes == 0:
                total_votes = -1
            context = {'selected_event': selected_event, 'comments': comments, 'form': form, 'comments_cnt': comments_cnt,
                       'poll': poll, 'dates': dates, 'if_voted': if_voted, 'poll_status': poll_status,
                       'poll_exist': poll_exist, 'total_votes': total_votes}
            return render(request, 'schedule/event_details.html', context)

        context = {'selected_event': selected_event, 'comments': comments, 'form': form, 'comments_cnt': comments_cnt}

        return render(request, 'schedule/event_details.html', context)

    if request.method == 'POST' and request.POST.get('new_content'):

        comment_id = request.POST.get('comment_id')
        new_content = request.POST.get('new_content')
        form = AddComment()
        update_comment = Comment.objects.filter(id=comment_id).update(content=new_content, if_edited=True)
        selected_event = Event.objects.filter(id=index)
        comments = Comment.objects.filter(event=index)
        comments_cnt = comments.count()

        context = {'selected_event': selected_event, 'comments': comments, 'form': form, 'myid': comment_id,
                   'comments_cnt': comments_cnt}

        return redirect('event_details', index)

    if request.method == 'POST' and request.POST.get('delete'):

        comment_id = request.POST.get('comment_id')

        delete_comment = Comment.objects.filter(id=comment_id).update(if_deleted=True)

        form = AddComment()
        selected_event = Event.objects.filter(id=index)
        comments = Comment.objects.filter(event=index)
        comments_cnt = comments.count()

        context = {'selected_event': selected_event, 'comments': comments, 'form': form, 'myid': comment_id,
                   'comments_cnt': comments_cnt}

        return render(request, 'schedule/event_details.html', context)


    if request.method == 'POST' and not request.POST.get('new_content') and request.POST.get('delete') != True:

        author = request.user
        event = Event.objects.filter(id=index)[0]
        created = datetime.now()
        content = request.POST.get('content')

        form = Comment(author=author, event=event, created=created, content=content)
        form.save()

        selected_event = Event.objects.filter(id=index)
        comments = Comment.objects.filter(event=index)
        comments_cnt = comments.count()
        mycmt = Comment.objects.filter(event=index).order_by('-id')[0]
        myid = mycmt.id

        context = {'selected_event': selected_event, 'comments': comments, 'form': form, 'myid': myid, 'comments_cnt': comments_cnt}

        return render(request, 'schedule/event_details.html', context)

    else:
        return redirect('events_list')


def password_reset_request(request):
    if request.method == "POST":
        domain = request.headers['Host']
        password_reset_form = PasswordResetForm(request.POST)

        try:

            if password_reset_form.is_valid():
                data = password_reset_form.cleaned_data['email']
                associated_users = User.objects.filter(Q(email=data))
                if associated_users.exists():
                    for user in associated_users:
                        subject = "Password Reset Requested"
                        email_template_name = "schedule/password_reset_email.txt"
                        c = {
                            "email": user.email,
                            'domain': domain,
                            'site_name': 'Interface',
                            "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                            "user": user,
                            'token': default_token_generator.make_token(user),
                            'protocol': 'http',
                        }
                        email = render_to_string(email_template_name, c)

                        host = 'lalala'
                        port = 123
                        username = 'lalala'
                        password = 'lalala'
                        use_tls = bool(1)
                        from_email = 'lalala'
                        with get_connection(host=host, port=port, username=username, password=password,
                                                use_tls=use_tls) as conn:
                            msg = EmailMessage(subject=subject, body=email,
                                                   from_email=from_email,
                                                   to=[user.email], connection=conn)
                            msg.send(fail_silently=True)

                            #send_mail(subject, email, settings.EMAIL_HOST_USER, [user.email], fail_silently=False)
                        return redirect("password_reset_done")
                else:
                    return redirect("password_reset_done")
            else:
                return redirect("password_reset_done")
        except:
            return redirect("password_reset_done")
    password_reset_form = PasswordResetForm()
    return render(request=request, template_name="schedule/password_reset_form.html",
                  context={"password_reset_form": password_reset_form})


def handler_403(request, exception):
    return render(request, 'schedule/403.html')


def handler_404(request, exception):
    return render(request, 'schedule/404.html')


def handler_400(request, exception):
    return render(request, 'schedule/400.html')


def handler_500(request):
    return render(request, 'schedule/500.html')

