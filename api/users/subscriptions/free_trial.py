from api.users.subscriptions.dao import UserSubscriptionDAO
from api.subscriptions.dao import SubscriptionDAO
from datetime import date, timedelta

async def assign_subscription(user_id, subscription_type):
    subscription = await SubscriptionDAO.find_one_or_none(order_by=None, title=subscription_type)
    if not subscription:
        return

    duration = 1 if subscription_type == "after registration trial" else None
    data = {
        'user_id': user_id,
        'subscription_level': subscription.level,
        'date_from': date.today(),
        'date_to': date.today() + timedelta(days=duration) if duration else None
    }

    await UserSubscriptionDAO.insert_data(data)

async def give_free_trial(user_id):
    await assign_subscription(user_id, "after registration trial")

async def give_free_sub(user_id):
    await assign_subscription(user_id, "free")
