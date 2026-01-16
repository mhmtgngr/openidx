import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Plus, Search, Users, MoreHorizontal, FolderTree } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { api } from '../lib/api'

interface Group {
  id: string
  name: string
  description: string
  parent_id: string | null
  member_count: number
  created_at: string
  updated_at: string
}

export function GroupsPage() {
  const [search, setSearch] = useState('')

  const { data: groups, isLoading } = useQuery({
    queryKey: ['groups', search],
    queryFn: () => api.get<Group[]>('/api/v1/identity/groups'),
  })

  const filteredGroups = groups?.filter(group =>
    group.name.toLowerCase().includes(search.toLowerCase()) ||
    group.description?.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Groups</h1>
          <p className="text-muted-foreground">Manage user groups and memberships</p>
        </div>
        <Button>
          <Plus className="mr-2 h-4 w-4" /> Create Group
        </Button>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
              <Input
                placeholder="Search groups..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-9"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <table className="w-full">
              <thead>
                <tr className="border-b bg-gray-50">
                  <th className="p-3 text-left text-sm font-medium">Group</th>
                  <th className="p-3 text-left text-sm font-medium">Description</th>
                  <th className="p-3 text-left text-sm font-medium">Members</th>
                  <th className="p-3 text-left text-sm font-medium">Type</th>
                  <th className="p-3 text-left text-sm font-medium">Created</th>
                  <th className="p-3 text-right text-sm font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr><td colSpan={6} className="p-4 text-center">Loading...</td></tr>
                ) : filteredGroups?.length === 0 ? (
                  <tr><td colSpan={6} className="p-4 text-center">No groups found</td></tr>
                ) : (
                  filteredGroups?.map((group) => (
                    <tr key={group.id} className="border-b hover:bg-gray-50">
                      <td className="p-3">
                        <div className="flex items-center gap-3">
                          <div className="h-10 w-10 rounded-lg bg-purple-100 flex items-center justify-center">
                            {group.parent_id ? (
                              <FolderTree className="h-5 w-5 text-purple-700" />
                            ) : (
                              <Users className="h-5 w-5 text-purple-700" />
                            )}
                          </div>
                          <div>
                            <p className="font-medium">{group.name}</p>
                            {group.parent_id && (
                              <p className="text-xs text-gray-500">Subgroup</p>
                            )}
                          </div>
                        </div>
                      </td>
                      <td className="p-3 text-gray-600 max-w-xs truncate">
                        {group.description || '-'}
                      </td>
                      <td className="p-3">
                        <div className="flex items-center gap-2">
                          <Users className="h-4 w-4 text-gray-400" />
                          {group.member_count}
                        </div>
                      </td>
                      <td className="p-3">
                        <Badge variant={group.parent_id ? 'secondary' : 'default'}>
                          {group.parent_id ? 'Subgroup' : 'Root'}
                        </Badge>
                      </td>
                      <td className="p-3 text-gray-500">
                        {new Date(group.created_at).toLocaleDateString()}
                      </td>
                      <td className="p-3 text-right">
                        <Button variant="ghost" size="icon">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
