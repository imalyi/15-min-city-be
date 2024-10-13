from api.dao.base import BaseDAO
from api.users.history.models import UserHistory

from api.database import async_session_maker
from sqlalchemy import select, insert
from sqlalchemy import literal_column

from sqlalchemy import select, func, text
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime, date

class UserHistoryDAO(BaseDAO):
    model = UserHistory

    @classmethod
    async def get_used_requests_today(cls, user_id: int):
        async with async_session_maker() as session:
            async with session.begin():
                stmt = select(UserHistory.request).where(
                    UserHistory.user_id == user_id,
                    func.date(UserHistory.created_at) == date.today()
                )
                
                result = await session.execute(stmt)
                #TODO fix this; use sqlalchemy tools
                addresses = set()
                for address in result:
                    addresses.add(address.request.get("start_point", {}).get("address").get("full_address"))
                    
                return len(addresses)
