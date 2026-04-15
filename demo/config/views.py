from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated


class PaymentView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({
            "message": "✅ GNAP auth success",
            "user": str(request.user),
            "auth": str(request.auth),
        })


class HealthView(APIView):
    def get(self, request):
        return Response({"status": "ok"})