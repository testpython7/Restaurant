from apiapp.models import MenuItem,Restaurant
from django.db.models.signals import post_save
from django.db.models.signals import post_delete
from django.dispatch import receiver
@receiver(post_save, sender=MenuItem)
def create_mymodel_row(sender, instance, created, **kwargs):
    if created:
        p=instance.restaurant
        d=p.id
        res=Restaurant.objects.get(id = d)
        res.menucount += 1
        res.save()

@receiver(post_delete, sender=MenuItem)
def post_delete_handler(sender, instance, **kwargs):
    p=instance.restaurant
    d=p.id
    res=Restaurant.objects.get(id = d)
    res.menucount -= 1
    res.save()