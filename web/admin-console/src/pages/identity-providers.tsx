import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useEffect, useState } from "react";
import { api, IdentityProvider } from "@/lib/api";
import { LoadingSpinner } from "@/components/ui/loading-spinner";
import { useToast } from "@/hooks/use-toast";

export function IdentityProvidersPage() {
  const [identityProviders, setIdentityProviders] = useState<IdentityProvider[]>(
    []
  );
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

  useEffect(() => {
    fetchIdentityProviders();
  }, []);

  const fetchIdentityProviders = async () => {
    try {
      setLoading(true);
      const data = await api.getIdentityProviders();
      setIdentityProviders(data);
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to fetch identity providers.",
        variant: "destructive",
      });
      console.error("Failed to fetch identity providers:", error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <LoadingSpinner />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Identity Providers</h1>
        <Button>Add Provider</Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Configured Providers</CardTitle>
          <CardDescription>
            Manage external identity providers for Single Sign-On (SSO).
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Issuer URL</TableHead>
                <TableHead>Enabled</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {identityProviders.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center">
                    No identity providers found.
                  </TableCell>
                </TableRow>
              ) : (
                identityProviders.map((provider) => (
                  <TableRow key={provider.id}>
                    <TableCell>{provider.name}</TableCell>
                    <TableCell>{provider.provider_type}</TableCell>
                    <TableCell>{provider.issuer_url}</TableCell>
                    <TableCell>{provider.enabled ? "Yes" : "No"}</TableCell>
                    <TableCell>
                      <Button variant="outline" size="sm">
                        Edit
                      </Button>
                      <Button
                        variant="destructive"
                        size="sm"
                        className="ml-2"
                      >
                        Delete
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
